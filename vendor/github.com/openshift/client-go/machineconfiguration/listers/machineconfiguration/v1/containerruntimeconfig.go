// Code generated by lister-gen. DO NOT EDIT.

package v1

import (
	v1 "github.com/openshift/api/machineconfiguration/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/listers"
	"k8s.io/client-go/tools/cache"
)

// ContainerRuntimeConfigLister helps list ContainerRuntimeConfigs.
// All objects returned here must be treated as read-only.
type ContainerRuntimeConfigLister interface {
	// List lists all ContainerRuntimeConfigs in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.ContainerRuntimeConfig, err error)
	// Get retrieves the ContainerRuntimeConfig from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1.ContainerRuntimeConfig, error)
	ContainerRuntimeConfigListerExpansion
}

// containerRuntimeConfigLister implements the ContainerRuntimeConfigLister interface.
type containerRuntimeConfigLister struct {
	listers.ResourceIndexer[*v1.ContainerRuntimeConfig]
}

// NewContainerRuntimeConfigLister returns a new ContainerRuntimeConfigLister.
func NewContainerRuntimeConfigLister(indexer cache.Indexer) ContainerRuntimeConfigLister {
	return &containerRuntimeConfigLister{listers.New[*v1.ContainerRuntimeConfig](indexer, v1.Resource("containerruntimeconfig"))}
}