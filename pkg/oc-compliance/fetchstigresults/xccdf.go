package fetchstigresults

import (
	"encoding/xml"
	"fmt"
	"sort"
)

const (
	xccdfURI  = "http://checklists.nist.gov/xccdf/1.2"
	xmlHeader = `<?xml version="1.0" encoding="UTF-8"?>` + "\n"
	// testSystem mirrors the CPE-style test-system attribute OpenSCAP writes on
	// its TestResult; DISA STIG Viewer expects this attribute to be present.
	testSystem = "cpe:/a:redhat:compliance_operator"
)

// ComplianceCheckResult status values (mirrors
// compliance.openshift.io/v1alpha1 ComplianceCheckStatus). Kept as local
// string constants so this plugin stays decoupled from the operator API types,
// matching the rest of the oc-compliance package.
const (
	statusPass          = "PASS"
	statusFail          = "FAIL"
	statusInfo          = "INFO"
	statusManual        = "MANUAL"
	statusError         = "ERROR"
	statusNotApplicable = "NOT-APPLICABLE"
	statusInconsistent  = "INCONSISTENT"
)

// statusRank orders ComplianceCheckResult statuses so that the most
// significant (worst) result wins when a single STIG rule is covered by
// several checks within one scan. A STIG rule is treated as Open (fail) if any
// contributing check fails.
func statusRank(status string) int {
	switch status {
	case statusFail:
		return 100
	case statusError:
		return 90
	case statusInconsistent:
		return 80
	case statusManual:
		return 70
	case statusInfo:
		return 60
	case statusPass:
		return 40
	case statusNotApplicable:
		return 30
	default:
		// Empty/no-result and anything unrecognized: rank above pass/n-a so a
		// missing verdict is not silently overridden by a benign one, but below
		// actionable statuses.
		return 50
	}
}

// statusToXCCDFResult maps a ComplianceCheckResult status to an XCCDF
// result-type enumeration value understood by DISA STIG Viewer.
func statusToXCCDFResult(status string) string {
	switch status {
	case statusPass:
		return "pass"
	case statusFail:
		return "fail"
	case statusError:
		return "error"
	case statusInfo:
		return "informational"
	case statusManual:
		return "notchecked"
	case statusNotApplicable:
		return "notapplicable"
	case statusInconsistent:
		return "error"
	default:
		return "unknown"
	}
}

// xccdfTestResult is a standalone XCCDF 1.2 TestResult document, matching the
// structure OpenSCAP writes with its --stig-viewer option (which DISA STIG
// Viewer imports natively). The default XML namespace is declared on the root,
// so all unprefixed children inherit it. Child element order follows the XCCDF
// schema: benchmark, title, target, rule-result*, score.
type xccdfTestResult struct {
	XMLName     xml.Name          `xml:"TestResult"`
	Xmlns       string            `xml:"xmlns,attr"`
	ID          string            `xml:"id,attr"`
	StartTime   string            `xml:"start-time,attr,omitempty"`
	EndTime     string            `xml:"end-time,attr,omitempty"`
	Version     string            `xml:"version,attr,omitempty"`
	TestSystem  string            `xml:"test-system,attr,omitempty"`
	Benchmark   benchmarkRef      `xml:"benchmark"`
	Title       string            `xml:"title"`
	Target      string            `xml:"target"`
	RuleResults []xccdfRuleResult `xml:"rule-result"`
	Score       xccdfScore        `xml:"score"`
}

type benchmarkRef struct {
	Href string `xml:"href,attr"`
	ID   string `xml:"id,attr,omitempty"`
}

type xccdfRuleResult struct {
	XMLName xml.Name `xml:"rule-result"`
	IDRef   string   `xml:"idref,attr"`
	Time    string   `xml:"time,attr,omitempty"`
	Weight  string   `xml:"weight,attr,omitempty"`
	Result  string   `xml:"result"`
}

type xccdfScore struct {
	System  string `xml:"system,attr"`
	Maximum string `xml:"maximum,attr"`
	Value   string `xml:",chardata"`
}

// buildTestResult assembles an XCCDF results document for a single scan. results
// maps each STIG SV rule id to its winning ComplianceCheckResult status. Each id
// becomes one <rule-result>, emitted in sorted order for stable output.
func buildTestResult(bindingName, scanName string, results map[string]string, timestamp string) *xccdfTestResult {
	svIDs := make([]string, 0, len(results))
	for sv := range results {
		svIDs = append(svIDs, sv)
	}
	sort.Strings(svIDs)

	var pass, fail int
	ruleResults := make([]xccdfRuleResult, 0, len(svIDs))
	for _, sv := range svIDs {
		res := statusToXCCDFResult(results[sv])
		switch res {
		case "pass":
			pass++
		case "fail":
			fail++
		}
		ruleResults = append(ruleResults, xccdfRuleResult{
			IDRef:  sv,
			Time:   timestamp,
			Weight: "1.000000",
			Result: res,
		})
	}

	// Default XCCDF scoring: percentage of passing rules among those that
	// produced a pass/fail verdict.
	score := 0.0
	if denom := pass + fail; denom > 0 {
		score = 100.0 * float64(pass) / float64(denom)
	}

	return &xccdfTestResult{
		Xmlns:      xccdfURI,
		ID:         fmt.Sprintf("xccdf_compliance.openshift.io_testresult_%s", scanName),
		StartTime:  timestamp,
		EndTime:    timestamp,
		Version:    "1.0",
		TestSystem: testSystem,
		Benchmark: benchmarkRef{
			Href: fmt.Sprintf("ssg-%s-ds.xml", scanName),
			ID:   fmt.Sprintf("xccdf_compliance.openshift.io_benchmark_%s", scanName),
		},
		Title:       fmt.Sprintf("DISA STIG results for scan %s (ScanSettingBinding %s)", scanName, bindingName),
		Target:      scanName,
		RuleResults: ruleResults,
		Score: xccdfScore{
			System:  "urn:xccdf:scoring:default",
			Maximum: "100.000000",
			Value:   fmt.Sprintf("%f", score),
		},
	}
}

func marshalTestResult(doc *xccdfTestResult) ([]byte, error) {
	body, err := xml.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xmlHeader), append(body, '\n')...), nil
}
