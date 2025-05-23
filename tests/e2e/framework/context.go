package framework

import (
	"fmt"
	"os"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/restmapper"
)

type Context struct {
	id         string
	cleanupFns []cleanupFn
	// the  namespace is deprecated
	// todo: remove before 1.0.0
	// use operatorNamespace or watchNamespace  instead
	namespace         string
	operatorNamespace string
	watchNamespace    string
	t                 *testing.T

	namespacedManPath string
	testType          string
	client            *frameworkClient
	kubeclient        kubernetes.Interface
	restMapper        *restmapper.DeferredDiscoveryRESTMapper
	cleanupOnError    bool
}

// todo(camilamacedo86): Remove the following line just added for we are able to deprecated TestCtx
// need to be done before: 1.0.0

// Deprecated: TestCtx exists for historical compatibility. Use Context instead.
type TestCtx = Context //nolint:golint

type CleanupOptions struct {
	TestContext   *Context
	Timeout       time.Duration
	RetryInterval time.Duration
}

type cleanupFn func() error

func (f *Framework) newContext(t *testing.T) *Context {
	// Context is used among others for namespace names where '/' is forbidden and must be 63 characters or less
	id := f.OperatorNamespace

	operatorNamespace := f.OperatorNamespace
	val, ok := os.LookupEnv(TestOperatorNamespaceEnv)
	if ok {
		operatorNamespace = val
	}

	watchNamespace := operatorNamespace
	ns, ok := os.LookupEnv(TestWatchNamespaceEnv)
	if ok {
		watchNamespace = ns
	}

	return &Context{
		id:                id,
		t:                 t,
		namespace:         operatorNamespace,
		operatorNamespace: operatorNamespace,
		watchNamespace:    watchNamespace,
		namespacedManPath: *f.NamespacedManPath,
		client:            f.Client,
		kubeclient:        f.KubeClient,
		restMapper:        f.restMapper,
		cleanupOnError:    f.cleanupOnError,
		testType:          f.testType,
	}
}

func NewContext(t *testing.T) *Context {
	return Global.newContext(t)
}

func (ctx *Context) GetID() string {
	return ctx.id
}

func (ctx *Context) Cleanup() {
	if ctx.t != nil {
		// The cleanup function will be skipped
		if ctx.t.Failed() && ctx.cleanupOnError {
			// Also, could we log the error here?
			s := fmt.Sprintf("Skipping cleanup function since -cleanupOnError is false and %s failed", ctx.t.Name())
			log.Info(s)
			return
		}
	}
	failed := false
	for i := len(ctx.cleanupFns) - 1; i >= 0; i-- {
		err := ctx.cleanupFns[i]()
		if err != nil {
			failed = true
			if ctx.t != nil {
				ctx.t.Errorf("A cleanup function failed with error: (%v)\n", err)
			} else {
				log.Errorf("A cleanup function failed with error: (%v)", err)
			}
		}
	}
	if ctx.t == nil && failed {
		log.Fatal("A cleanup function failed")
	}

}

func (ctx *Context) GetTestType() string {
	return ctx.testType
}

func (ctx *Context) AddCleanupFn(fn cleanupFn) {
	ctx.cleanupFns = append(ctx.cleanupFns, fn)
}
