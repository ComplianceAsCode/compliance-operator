package rerunnow

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/common"
)

type ComplianceSuiteHelper struct {
	kuser common.KubeClientUser
	gvk   schema.GroupVersionResource
	kind  string
	name  string
	genericclioptions.IOStreams
}

func NewComplianceSuiteHelper(kuser common.KubeClientUser, name string, streams genericclioptions.IOStreams) common.ObjectHelper {
	return &ComplianceSuiteHelper{
		kuser: kuser,
		name:  name,
		kind:  "ComplianceSuite",
		gvk: schema.GroupVersionResource{
			Group:    common.CmpAPIGroup,
			Version:  common.CmpResourceVersion,
			Resource: "compliancesuites",
		},
		IOStreams: streams,
	}
}

func (h *ComplianceSuiteHelper) Handle() error {
	// Get target resource
	res, err := h.kuser.DynamicClient().Resource(h.gvk).Namespace(h.kuser.GetNamespace()).Get(context.TODO(), h.name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("Unable to get resource %s/%s of type %s: %s", h.kuser.GetNamespace(), h.name, h.kind, err)
	}

	// Get needed data
	scanNames, err := common.GetScanNamesFromSuite(res)
	if err != nil {
		return err
	}

	fmt.Fprintf(h.Out, "Rerunning scans from '%s': %s\n", h.name, strings.Join(scanNames, ", "))

	for _, scanName := range scanNames {
		helper := NewComplianceScanHelper(h.kuser, scanName, h.IOStreams)
		if err = helper.Handle(); err != nil {
			return fmt.Errorf("Unable to process results from suite %s: %s", h.name, err)
		}
	}
	return nil
}
