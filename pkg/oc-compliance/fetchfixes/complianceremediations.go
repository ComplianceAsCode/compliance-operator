package fetchfixes

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sserial "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/common"
	"github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/fetchfixes/emb"
)

type ComplianceRemediationHelper struct {
	FixPersister
	kuser common.KubeClientUser
	gvk   schema.GroupVersionResource
	kind  string
	name  string
	emb   emb.ExtraManifestBuilder
}

func NewComplianceRemediationHelper(
	kuser common.KubeClientUser, name string, outputPath string, mcRoles []string,
	emb emb.ExtraManifestBuilder, streams genericclioptions.IOStreams,
) common.ObjectHelper {
	return &ComplianceRemediationHelper{
		FixPersister: FixPersister{
			outputPath: outputPath,
			mcRoles:    mcRoles,
			IOStreams:   streams,
		},
		kuser: kuser,
		name:  name,
		emb:   emb,
		kind:  "ComplianceRemediation",
		gvk: schema.GroupVersionResource{
			Group:    common.CmpAPIGroup,
			Version:  common.CmpResourceVersion,
			Resource: "complianceremediations",
		},
	}
}

func (h *ComplianceRemediationHelper) Handle() error {
	r, err := h.kuser.DynamicClient().Resource(h.gvk).Namespace(h.kuser.GetNamespace()).Get(context.TODO(), h.name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	current, err := h.getCurrentObject(r)
	if err != nil {
		return err
	}

	yamlSerializer := k8sserial.NewYAMLSerializer(k8sserial.DefaultMetaFactory, nil, nil)

	h.emb.BuildObjectContext(current, r)

	fileName := h.name
	err = h.handleObjectPersistence(yamlSerializer, fileName, current)
	if err != nil {
		return err
	}

	return nil
}

func (h *ComplianceRemediationHelper) getCurrentObject(obj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	rem, found, err := unstructured.NestedMap(obj.Object, "spec", "current", "object")
	if err != nil {
		return nil, fmt.Errorf("Unable to get remediations of %s/%s of type %s: %s", obj.GetNamespace(), obj.GetName(), h.kind, err)
	}
	if !found {
		return nil, fmt.Errorf("no found remediations for %s/%s of type %s: %s", obj.GetNamespace(), obj.GetName(), h.kind, err)
	}

	remobj := &unstructured.Unstructured{Object: rem}
	return remobj, nil
}
