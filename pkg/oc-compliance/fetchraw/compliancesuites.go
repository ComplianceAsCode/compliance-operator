package fetchraw

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/common"
)

type ComplianceSuiteHelper struct {
	kuser      common.KubeClientUser
	gvk        schema.GroupVersionResource
	name       string
	kind       string
	outputPath string
	image      string
	html       bool
	genericclioptions.IOStreams
}

func NewComplianceSuiteHelper(kuser common.KubeClientUser, name, outputPath, image string, html bool, streams genericclioptions.IOStreams) common.ObjectHelper {
	return &ComplianceSuiteHelper{
		kuser:      kuser,
		name:       name,
		kind:       "ComplianceSuite",
		outputPath: outputPath,
		html:       html,
		image:      image,
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

	fmt.Fprintf(h.Out, "Fetching results for %s scans: %s\n", h.name, strings.Join(scanNames, ", "))

	for _, scanName := range scanNames {
		scanDir := path.Join(h.outputPath, scanName)
		if err := os.Mkdir(scanDir, 0700); err != nil {
			return fmt.Errorf("Unable to create directory %s: %s", scanDir, err)
		}
		helper := NewComplianceScanHelper(h.kuser, scanName, scanDir, h.image, h.html, h.IOStreams)
		if err = helper.Handle(); err != nil {
			return fmt.Errorf("Unable to process results from suite %s: %s", h.name, err)
		}
	}
	return nil
}
