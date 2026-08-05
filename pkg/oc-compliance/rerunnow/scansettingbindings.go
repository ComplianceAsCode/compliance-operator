package rerunnow

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/common"
)

type ScanSettingBindingHelper struct {
	kuser common.KubeClientUser
	gvk   schema.GroupVersionResource
	name  string
	kind  string
	genericclioptions.IOStreams
}

func NewScanSettingBindingHelper(kuser common.KubeClientUser, name string, streams genericclioptions.IOStreams) common.ObjectHelper {
	return &ScanSettingBindingHelper{
		kuser: kuser,
		name:  name,
		kind:  "ScanSettingBinding",
		gvk: schema.GroupVersionResource{
			Group:    common.CmpAPIGroup,
			Version:  common.CmpResourceVersion,
			Resource: "scansettingbindings",
		},
		IOStreams: streams,
	}
}

func (h *ScanSettingBindingHelper) Handle() error {
	// Get target resource
	res, err := h.kuser.DynamicClient().Resource(h.gvk).Namespace(h.kuser.GetNamespace()).Get(context.TODO(), h.name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("Unable to get resource %s/%s of type %s: %s", h.kuser.GetNamespace(), h.name, h.kind, err)
	}
	suiteName := res.GetName()

	helper := NewComplianceSuiteHelper(h.kuser, suiteName, h.IOStreams)
	return helper.Handle()
}
