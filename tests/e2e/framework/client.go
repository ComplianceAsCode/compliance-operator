package framework

import (
	goctx "context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	dynclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type frameworkClient struct {
	dynclient.Client
}

var _ FrameworkClient = &frameworkClient{}

type FrameworkClient interface {
	Get(gCtx goctx.Context, key dynclient.ObjectKey, obj dynclient.Object) error
	List(gCtx goctx.Context, list dynclient.ObjectList, opts ...dynclient.ListOption) error
	Create(gCtx goctx.Context, obj dynclient.Object, cleanupOptions *CleanupOptions) error
	Delete(gCtx goctx.Context, obj dynclient.Object, opts ...dynclient.DeleteOption) error
	Update(gCtx goctx.Context, obj dynclient.Object) error
}

func retryOnAnyError(err error) bool {
	return !apierrors.IsNotFound(err)
}

// Create uses the dynamic client to create an object and then adds a
// cleanup function to delete it when Cleanup is called. In addition to
// the standard controller-runtime client options
func (f *frameworkClient) Create(gCtx goctx.Context, obj dynclient.Object, cleanupOptions *CleanupOptions) error {
	objCopy := obj.DeepCopyObject()
	err := f.Client.Create(gCtx, obj)
	if err != nil {
		return err
	}
	// if no test context exists, cannot add finalizer function or print to testing log
	if cleanupOptions == nil || cleanupOptions.TestContext == nil {
		return nil
	}
	key := dynclient.ObjectKeyFromObject(obj)
	// this function fails silently if t is nil
	if cleanupOptions.TestContext.t != nil {
		cleanupOptions.TestContext.t.Logf("resource type %+v with namespace/name (%+v) created\n",
			objCopy.GetObjectKind().GroupVersionKind().Kind, key)
	}
	cleanupOptions.TestContext.AddCleanupFn(func() error {
		err = retry.OnError(retry.DefaultRetry, retryOnAnyError, func() error {
			return f.Client.Delete(gCtx, obj)
		})
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		if cleanupOptions.Timeout == 0 && cleanupOptions.RetryInterval != 0 {
			return fmt.Errorf("retry interval is set but timeout is not; cannot poll for cleanup")
		} else if cleanupOptions.Timeout != 0 && cleanupOptions.RetryInterval == 0 {
			return fmt.Errorf("timeout is set but retry interval is not; cannot poll for cleanup")
		}
		if cleanupOptions.Timeout != 0 && cleanupOptions.RetryInterval != 0 {
			return wait.PollImmediate(cleanupOptions.RetryInterval, cleanupOptions.Timeout, func() (bool, error) {
				err = f.Client.Get(gCtx, key, obj)
				if err != nil {
					if apierrors.IsNotFound(err) {
						if cleanupOptions.TestContext.t != nil {
							cleanupOptions.TestContext.t.Logf("resource type %+v with namespace/name (%+v)"+
								" successfully deleted\n", objCopy.GetObjectKind().GroupVersionKind().Kind, key)
						}
						return true, nil
					}
					return false, fmt.Errorf("error encountered during deletion of resource type %v with"+
						" namespace/name (%+v): %v", objCopy.GetObjectKind().GroupVersionKind().Kind, key, err)
				}
				if cleanupOptions.TestContext.t != nil {
					cleanupOptions.TestContext.t.Logf("waiting for deletion of resource type %+v with"+
						" namespace/name (%+v)\n", objCopy.GetObjectKind().GroupVersionKind().Kind, key)
				}
				return false, nil
			})
		}
		return nil
	})
	return nil
}

func (f *frameworkClient) CreateWithoutCleanup(gCtx goctx.Context, obj dynclient.Object) error {
	err := f.Client.Create(gCtx, obj)
	if err != nil {
		return err
	}
	return nil
}

func (f *frameworkClient) Get(gCtx goctx.Context, key dynclient.ObjectKey, obj dynclient.Object) error {
	return f.Client.Get(gCtx, key, obj)
}

func (f *frameworkClient) List(gCtx goctx.Context, list dynclient.ObjectList, opts ...dynclient.ListOption) error {
	return f.Client.List(gCtx, list, opts...)
}

func (f *frameworkClient) Delete(gCtx goctx.Context, obj dynclient.Object, opts ...dynclient.DeleteOption) error {
	return f.Client.Delete(gCtx, obj, opts...)
}

func (f *frameworkClient) Update(gCtx goctx.Context, obj dynclient.Object) error {
	return f.Client.Update(gCtx, obj)
}
