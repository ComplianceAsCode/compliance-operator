package common

import (
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	CmpAPIGroup        = "compliance.openshift.io"
	CmpResourceVersion = "v1alpha1"
	RetryInterval      = time.Second * 2
	Timeout            = time.Minute * 20
)

func GVR(resource string) schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    CmpAPIGroup,
		Version:  CmpResourceVersion,
		Resource: resource,
	}
}
