package emb

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const NoopBuilderName = "default"

type NoopManifestBuilder struct {
}

func NewNoopManifestBuilder() ExtraManifestBuilder {
	return &NoopManifestBuilder{}
}

func (nmb *NoopManifestBuilder) BuildObjectContext(fix, objOwner *unstructured.Unstructured) error {
	return nil
}

func (nmb *NoopManifestBuilder) FlushManifests(path string, roles []string) error {
	return nil
}
