package rerunnow

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/common"
)

const (
	rescanAnnotation = "compliance.openshift.io/rescan"
)

type ComplianceScanHelper struct {
	kuser common.KubeClientUser
	gvk   schema.GroupVersionResource
	kind  string
	name  string
	genericclioptions.IOStreams
}

func NewComplianceScanHelper(kuser common.KubeClientUser, name string, streams genericclioptions.IOStreams) common.ObjectHelper {
	return &ComplianceScanHelper{
		kuser: kuser,
		name:  name,
		kind:  "ComplianceScan",
		gvk: schema.GroupVersionResource{
			Group:    common.CmpAPIGroup,
			Version:  common.CmpResourceVersion,
			Resource: "compliancescans",
		},
		IOStreams: streams,
	}
}

func (h *ComplianceScanHelper) Handle() error {
	scan, err := h.kuser.DynamicClient().Resource(h.gvk).Namespace(h.kuser.GetNamespace()).Get(context.TODO(), h.name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	annotations := scan.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[rescanAnnotation] = ""
	scan.SetAnnotations(annotations)

	fmt.Fprintf(h.Out, "Re-running scan '%s/%s'\n", h.kuser.GetNamespace(), h.name)
	_, err = h.kuser.DynamicClient().Resource(h.gvk).Namespace(h.kuser.GetNamespace()).Update(context.TODO(), scan, metav1.UpdateOptions{})
	return err
}
