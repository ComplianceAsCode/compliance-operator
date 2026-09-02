package fetchstigresults

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/common"
)

const (
	// stigRuleAnnotationKey holds the DISA STIG rule id(s) for a check, as
	// parsed from the content's srg-stig-tools reference. Multiple ids are
	// semicolon-separated, e.g. "SV-257564r1050650_rule;SV-257565r1050651_rule".
	stigRuleAnnotationKey = "control.compliance.openshift.io/STIG-RULE"
	scanNameLabel         = "compliance.openshift.io/scan-name"
	suiteLabel            = "compliance.openshift.io/suite"
)

// ScanSettingBindingHelper generates DISA STIG Viewer XCCDF result files from
// the ComplianceCheckResults produced by a ScanSettingBinding.
type ScanSettingBindingHelper struct {
	kuser      common.KubeClientUser
	name       string
	outputPath string
	scan       string
	perScan    bool
	ssbgvr     schema.GroupVersionResource
	ccrgvr     schema.GroupVersionResource
	genericclioptions.IOStreams
}

func NewScanSettingBindingHelper(kuser common.KubeClientUser, name, outputPath, scan string, perScan bool, streams genericclioptions.IOStreams) common.ObjectHelper {
	return &ScanSettingBindingHelper{
		kuser:      kuser,
		name:       name,
		outputPath: outputPath,
		scan:       scan,
		perScan:    perScan,
		ssbgvr:     common.GVR("scansettingbindings"),
		ccrgvr:     common.GVR("compliancecheckresults"),
		IOStreams:  streams,
	}
}

func (h *ScanSettingBindingHelper) Handle() error {
	ns := h.kuser.GetNamespace()

	ssb, err := h.kuser.DynamicClient().Resource(h.ssbgvr).Namespace(ns).Get(context.TODO(), h.name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to get ScanSettingBinding %s/%s: %w", ns, h.name, err)
	}

	// The ComplianceSuite generated from a binding is referenced by
	// status.outputRef and shares the binding's name; fall back to the binding
	// name if the status isn't populated yet.
	suiteName, found, err := unstructured.NestedString(ssb.Object, "status", "outputRef", "name")
	if err != nil {
		return fmt.Errorf("unable to read status.outputRef.name of ScanSettingBinding %s: %w", h.name, err)
	}
	if !found || suiteName == "" {
		suiteName = h.name
	}

	selector := fmt.Sprintf("%s=%s", suiteLabel, suiteName)
	ccrList, err := h.kuser.DynamicClient().Resource(h.ccrgvr).Namespace(ns).List(context.TODO(), metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return fmt.Errorf("unable to list ComplianceCheckResults for suite %s: %w", suiteName, err)
	}
	if len(ccrList.Items) == 0 {
		return fmt.Errorf("no ComplianceCheckResults found for ScanSettingBinding %s (suite %s); has the scan finished?", h.name, suiteName)
	}

	// scans maps scan name -> STIG SV rule id -> winning status. Within a scan,
	// duplicate SV ids are collapsed worst-status-wins; the scans are then either
	// combined into one file (default), split per scan, or filtered to one.
	scans := map[string]map[string]string{}
	for i := range ccrList.Items {
		ccr := &ccrList.Items[i]

		stigRules := ccr.GetAnnotations()[stigRuleAnnotationKey]
		if strings.TrimSpace(stigRules) == "" {
			// Not a STIG-mapped rule; skip it.
			continue
		}

		scanName := ccr.GetLabels()[scanNameLabel]
		if scanName == "" {
			scanName = suiteName
		}
		if scans[scanName] == nil {
			scans[scanName] = map[string]string{}
		}

		status, _, _ := unstructured.NestedString(ccr.Object, "status")
		for _, sv := range strings.Split(stigRules, ";") {
			sv = strings.TrimSpace(sv)
			if sv == "" {
				continue
			}
			addResult(scans[scanName], sv, status)
		}
	}

	if len(scans) == 0 {
		return fmt.Errorf("found %d results for suite %s, but none carried a %q annotation; is this a STIG ScanSettingBinding?",
			len(ccrList.Items), suiteName, stigRuleAnnotationKey)
	}

	switch {
	case h.scan != "":
		// Restrict output to a single scan; error with the list of available
		// scans if it doesn't exist.
		only, ok := scans[h.scan]
		if !ok {
			return fmt.Errorf("scan %q not found in ScanSettingBinding %s; available scans: %s",
				h.scan, h.name, strings.Join(sortedKeys(scans), ", "))
		}
		scans = map[string]map[string]string{h.scan: only}
	case !h.perScan:
		// Default: collapse every scan into a single file keyed by the binding
		// name, worst-status-wins across all scans for each SV rule id.
		merged := map[string]string{}
		for _, results := range scans {
			for sv, status := range results {
				addResult(merged, sv, status)
			}
		}
		scans = map[string]map[string]string{h.name: merged}
	}

	if err := os.MkdirAll(h.outputPath, 0755); err != nil {
		return fmt.Errorf("unable to create output directory %s: %w", h.outputPath, err)
	}

	timestamp := time.Now().UTC().Format(time.RFC3339)
	for _, scanName := range sortedKeys(scans) {
		doc := buildTestResult(h.name, scanName, scans[scanName], timestamp)
		out, err := marshalTestResult(doc)
		if err != nil {
			return fmt.Errorf("unable to render XCCDF for scan %s: %w", scanName, err)
		}
		fpath := filepath.Join(h.outputPath, scanName+".xml")
		if err := os.WriteFile(fpath, out, 0644); err != nil {
			return fmt.Errorf("unable to write %s: %w", fpath, err)
		}
		fmt.Fprintf(h.Out, "Wrote %d STIG rule results to %s\n", len(scans[scanName]), fpath)
	}

	return nil
}

// addResult records status for an SV rule id in m, keeping the worst status when
// the id is already present (see statusRank).
func addResult(m map[string]string, sv, status string) {
	if cur, ok := m[sv]; !ok || statusRank(status) > statusRank(cur) {
		m[sv] = status
	}
}

// sortedKeys returns the keys of m in ascending order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
