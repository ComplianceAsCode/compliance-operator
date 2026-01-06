package framework

import (
	goctx "context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/pborman/uuid"
	extscheme "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/scheme"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	cached "k8s.io/client-go/discovery/cached"
	"k8s.io/client-go/kubernetes"
	cgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	dynclient "sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// Global framework struct
	Global *Framework
)

// from the old operator-sdk scaffold constants
const (
	// Separator to statically create directories.
	filePathSep = string(filepath.Separator)

	// dirs
	CmdDir      = "cmd"
	ManagerDir  = CmdDir + filePathSep + "manager"
	BuildDir    = "build"
	BuildBinDir = BuildDir + filePathSep + "_output" + filePathSep + "bin"
)

const (
	// KubeConfigEnvVar defines the env variable KUBECONFIG which
	// contains the kubeconfig file path.
	KubeConfigEnvVar = "KUBECONFIG"

	// WatchNamespaceEnvVar is the constant for env variable WATCH_NAMESPACE
	// which is the namespace where the watch activity happens.
	// this value is empty if the operator is running with clusterScope.
	WatchNamespaceEnvVar = "WATCH_NAMESPACE"
)

type Framework struct {
	Client            *frameworkClient
	KubeConfig        *rest.Config
	KubeClient        kubernetes.Interface
	Scheme            *runtime.Scheme
	NamespacedManPath *string
	OperatorNamespace string
	WatchNamespace    string
	Platform          string

	restMapper *restmapper.DeferredDiscoveryRESTMapper

	projectRoot        string
	globalManPath      string
	localOperatorArgs  string
	kubeconfigPath     string
	testType           string
	schemeMutex        sync.Mutex
	LocalOperator      bool
	cleanupOnError     bool
	installMethod      string
	olmChannel         string
	olmSource          string
	olmSourceNamespace string
}

type frameworkOpts struct {
	projectRoot        string
	kubeconfigPath     string
	globalManPath      string
	namespacedManPath  string
	localOperatorArgs  string
	testType           string
	isLocalOperator    bool
	cleanupOnError     bool
	platform           string
	installMethod      string
	olmChannel         string
	olmSource          string
	olmSourceNamespace string
}

const (
	TestTypeAll      = "all"
	TestTypeParallel = "parallel"
	TestTypeSerial   = "serial"
)

const (
	InstallMethodManifest     = "manifest"
	InstallMethodSubscription = "subscription"
)

const (
	ProjRootFlag           = "root"
	KubeConfigFlag         = "kubeconfig"
	NamespacedManPathFlag  = "namespacedMan"
	GlobalManPathFlag      = "globalMan"
	LocalOperatorFlag      = "localOperator"
	LocalOperatorArgs      = "localOperatorArgs"
	CleanupOnErrorFlag     = "cleanupOnError"
	TestTypeFlag           = "testType"
	PlatformFlag           = "platform"
	InstallMethodFlag      = "installMethod"
	OLMChannelFlag         = "olmChannel"
	OLMSourceFlag          = "olmSource"
	OLMSourceNamespaceFlag = "olmSourceNamespace"

	TestOperatorNamespaceEnv = "TEST_OPERATOR_NAMESPACE"
	TestWatchNamespaceEnv    = "TEST_WATCH_NAMESPACE"
)

func (opts *frameworkOpts) addToFlagSet(flagset *flag.FlagSet) {
	flagset.StringVar(&opts.projectRoot, ProjRootFlag, "", "path to project root")
	flagset.StringVar(&opts.namespacedManPath, NamespacedManPathFlag, "", "path to rbac manifest")
	flagset.BoolVar(&opts.isLocalOperator, LocalOperatorFlag, false,
		"enable if operator is running locally (not in cluster)")
	flagset.StringVar(&opts.globalManPath, GlobalManPathFlag, "", "path to operator manifest")
	flagset.StringVar(&opts.localOperatorArgs, LocalOperatorArgs, "",
		"flags that the operator needs (while using --up-local). example: \"--flag1 value1 --flag2=value2\"")
	flagset.BoolVar(&opts.cleanupOnError, CleanupOnErrorFlag, false,
		"If set to true, the test runner will attempt to cleanup all test resources "+
			"if the test failed. By default, test resources are not cleaned up "+
			"after failed tests to help debug test issues. This option has no effect on successful test runs, "+
			"in which case test resources are automatically cleaned up.")
	flagset.StringVar(&opts.testType, TestTypeFlag, TestTypeAll,
		"Defines the type of tests to run. (Options: all, serial, parallel)")
	flagset.StringVar(&opts.platform, PlatformFlag, "openshift",
		"The type of deployment hosting the tests. Options include \"openshift\" and \"rosa\".")
	flagset.StringVar(&opts.installMethod, InstallMethodFlag, InstallMethodManifest,
		"Method to install the compliance operator. Options: \"manifest\" (default) or \"subscription\" (OLM-based)")
	flagset.StringVar(&opts.olmChannel, OLMChannelFlag, "stable",
		"OLM subscription channel (only used when installMethod is \"subscription\")")
	flagset.StringVar(&opts.olmSource, OLMSourceFlag, "redhat-operators",
		"OLM catalog source (only used when installMethod is \"subscription\")")
	flagset.StringVar(&opts.olmSourceNamespace, OLMSourceNamespaceFlag, "openshift-marketplace",
		"OLM catalog source namespace (only used when installMethod is \"subscription\")")
}

func newFramework(opts *frameworkOpts) (*Framework, error) {
	kubeconfig, _, err := GetKubeconfigAndNamespace(opts.kubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to build the kubeconfig: %w", err)
	}

	var operatorNamespace string
	ns, ok := os.LookupEnv(TestOperatorNamespaceEnv)
	if ok && ns != "" {
		operatorNamespace = ns
	} else {
		operatorNamespace = "osdk-e2e-" + uuid.New()
	}

	kubeclient, err := kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build the kubeclient: %w", err)
	}

	scheme := runtime.NewScheme()
	if err := cgoscheme.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add cgo scheme to runtime scheme: %w", err)
	}
	if err := extscheme.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add api extensions scheme to runtime scheme: %w", err)
	}

	cachedDiscoveryClient := cached.NewMemCacheClient(kubeclient.Discovery())
	restMapper := restmapper.NewDeferredDiscoveryRESTMapper(cachedDiscoveryClient)
	restMapper.Reset()

	dynClient, err := dynclient.New(kubeconfig, dynclient.Options{Scheme: scheme, Mapper: restMapper})
	if err != nil {
		return nil, fmt.Errorf("failed to build the dynamic client: %w", err)
	}
	framework := &Framework{
		Client:            &frameworkClient{Client: dynClient},
		KubeConfig:        kubeconfig,
		KubeClient:        kubeclient,
		Scheme:            scheme,
		NamespacedManPath: &opts.namespacedManPath,
		OperatorNamespace: operatorNamespace,
		Platform:          opts.platform,
		LocalOperator:     opts.isLocalOperator,

		projectRoot:        opts.projectRoot,
		globalManPath:      opts.globalManPath,
		localOperatorArgs:  opts.localOperatorArgs,
		kubeconfigPath:     opts.kubeconfigPath,
		restMapper:         restMapper,
		cleanupOnError:     opts.cleanupOnError,
		testType:           opts.testType,
		installMethod:      opts.installMethod,
		olmChannel:         opts.olmChannel,
		olmSource:          opts.olmSource,
		olmSourceNamespace: opts.olmSourceNamespace,
	}
	return framework, nil
}

type addToSchemeFunc func(*runtime.Scheme) error

// AddToFrameworkScheme allows users to add the scheme for their custom resources
// to the framework's scheme for use with the dynamic client. The user provides
// the addToScheme function (located in the register.go file of their operator
// project) and the List struct for their custom resource. For example, for a
// memcached operator, the list stuct may look like:
// &MemcachedList{}
// The List object is needed because the CRD has not always been fully registered
// by the time this function is called. If the CRD takes more than 5 seconds to
// become ready, this function throws an error
func AddToFrameworkScheme(addToScheme addToSchemeFunc, obj dynclient.ObjectList) error {
	return Global.addToScheme(addToScheme, obj)
}

func (f *Framework) addToScheme(addToScheme addToSchemeFunc, obj dynclient.ObjectList) error {
	f.schemeMutex.Lock()
	defer f.schemeMutex.Unlock()

	err := addToScheme(f.Scheme)
	if err != nil {
		return err
	}
	f.restMapper.Reset()
	dynClient, err := dynclient.New(f.KubeConfig, dynclient.Options{Scheme: f.Scheme, Mapper: f.restMapper})
	if err != nil {
		return fmt.Errorf("failed to initialize new dynamic client: %w", err)
	}
	err = wait.PollImmediate(time.Second, time.Second*10, func() (done bool, err error) {
		ns, ok := os.LookupEnv(TestOperatorNamespaceEnv)
		if ok && ns != "" {
			err = dynClient.List(goctx.TODO(), obj, dynclient.InNamespace(f.OperatorNamespace))
		} else {
			err = dynClient.List(goctx.TODO(), obj, dynclient.InNamespace("default"))
		}
		if err != nil {
			f.restMapper.Reset()
			return false, nil
		}
		f.Client = &frameworkClient{Client: dynClient}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("failed to build the dynamic client: %w", err)
	}
	return nil
}
