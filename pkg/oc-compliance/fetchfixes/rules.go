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

type RuleHelper struct {
	FixPersister
	kuser common.KubeClientUser
	gvk   schema.GroupVersionResource
	kind  string
	name  string
	emb   emb.ExtraManifestBuilder
}

func NewRuleHelper(
	kuser common.KubeClientUser, name string, outputPath string, mcRoles []string,
	emb emb.ExtraManifestBuilder, streams genericclioptions.IOStreams) common.ObjectHelper {
	return &RuleHelper{
		FixPersister: FixPersister{
			outputPath: outputPath,
			mcRoles:    mcRoles,
			IOStreams:   streams,
		},
		kuser: kuser,
		name:  name,
		emb:   emb,
		kind:  "Rule",
		gvk: schema.GroupVersionResource{
			Group:    common.CmpAPIGroup,
			Version:  common.CmpResourceVersion,
			Resource: "rules",
		},
	}
}

func (h *RuleHelper) Handle() error {
	r, err := h.kuser.DynamicClient().Resource(h.gvk).Namespace(h.kuser.GetNamespace()).Get(context.TODO(), h.name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	fixes, err := h.getAvailableFixes(r)
	if err != nil {
		return err
	}

	if len(fixes) == 0 {
		fmt.Fprintf(h.Out, "No fixes to persist for rule '%s'\n", r.GetName())
		return nil
	}

	yamlSerializer := k8sserial.NewYAMLSerializer(k8sserial.DefaultMetaFactory, nil, nil)

	needsSuffix := len(fixes) > 1
	for idx, fix := range fixes {
		fileName := r.GetName()
		if needsSuffix {
			fileName = fmt.Sprintf("%s-%d", r.GetName(), idx)
		}
		h.emb.BuildObjectContext(fix, r)
		err := h.handleObjectPersistence(yamlSerializer, fileName, fix)
		if err != nil {
			return err
		}
	}

	return nil
}

func (h *RuleHelper) getAvailableFixes(obj *unstructured.Unstructured) ([]*unstructured.Unstructured, error) {
	fixes, found, err := unstructured.NestedSlice(obj.Object, "availableFixes")
	if err != nil {
		return nil, fmt.Errorf("Unable to get fixes of %s/%s of type %s: %s", obj.GetNamespace(), obj.GetName(), h.kind, err)
	}
	if !found {
		return nil, nil
	}

	output := []*unstructured.Unstructured{}
	for _, fixIf := range fixes {
		fix, ok := fixIf.(map[string]interface{})
		if !ok {
			fmt.Fprintf(h.ErrOut, "WARNING: Rule '%s/%s' has a malformed fix. Expected a map.", obj.GetNamespace(), obj.GetName())
			continue
		}
		fixobjraw, found, err := unstructured.NestedMap(fix, "fixObject")
		if err != nil {
			fmt.Fprintf(h.ErrOut, "WARNING: Rule '%s/%s' has a malformed fix. Couldn't get 'fixObject' key.", obj.GetNamespace(), obj.GetName())
			continue
		}
		if !found {
			fmt.Fprintf(h.ErrOut, "WARNING: Rule '%s/%s' has a malformed fix. 'fixObject' key not found.", obj.GetNamespace(), obj.GetName())
			continue
		}
		fixobj := &unstructured.Unstructured{Object: fixobjraw}
		output = append(output, fixobj)
	}
	return output, nil
}
