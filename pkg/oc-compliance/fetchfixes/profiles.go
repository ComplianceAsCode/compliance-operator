package fetchfixes

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/common"
	"github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/fetchfixes/emb"
)

type ProfileHelper struct {
	kuser      common.KubeClientUser
	gvk        schema.GroupVersionResource
	kind       string
	name       string
	outputPath string
	mcRoles    []string
	emb        emb.ExtraManifestBuilder
	genericclioptions.IOStreams
}

func NewProfileHelper(
	kuser common.KubeClientUser, name string, outputPath string, mcRoles []string,
	emb emb.ExtraManifestBuilder, streams genericclioptions.IOStreams,
) common.ObjectHelper {
	return &ProfileHelper{
		kuser: kuser,
		name:  name,
		kind:  "Profile",
		gvk: schema.GroupVersionResource{
			Group:    common.CmpAPIGroup,
			Version:  common.CmpResourceVersion,
			Resource: "profiles",
		},
		outputPath: outputPath,
		mcRoles:    mcRoles,
		emb:        emb,
		IOStreams:   streams,
	}
}

func (h *ProfileHelper) Handle() error {
	p, err := h.kuser.DynamicClient().Resource(h.gvk).Namespace(h.kuser.GetNamespace()).Get(context.TODO(), h.name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	rules, err := common.GetRulesFromProfile(p)
	for _, r := range rules {
		rh := NewRuleHelper(h.kuser, r, h.outputPath, h.mcRoles, h.emb, h.IOStreams)
		rh.Handle()
	}
	return nil
}
