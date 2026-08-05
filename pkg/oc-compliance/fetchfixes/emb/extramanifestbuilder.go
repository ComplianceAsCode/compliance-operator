package emb

import "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

type ExtraManifestBuilder interface {
	BuildObjectContext(fix, ctx *unstructured.Unstructured) error
	FlushManifests(path string, roles []string) error
}
