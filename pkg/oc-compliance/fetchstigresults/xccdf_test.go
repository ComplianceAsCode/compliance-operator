package fetchstigresults

import (
	"strings"
	"testing"
)

func TestAddResultWorstStatusWins(t *testing.T) {
	tests := []struct {
		name     string
		statuses []string
		want     string
	}{
		{"fail beats pass", []string{statusPass, statusFail}, statusFail},
		{"order independent", []string{statusFail, statusPass}, statusFail},
		{"error beats manual", []string{statusManual, statusError}, statusError},
		{"pass beats not-applicable", []string{statusNotApplicable, statusPass}, statusPass},
		{"no-result beats pass", []string{statusPass, ""}, ""},
		{"single value", []string{statusInfo}, statusInfo},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := map[string]string{}
			for _, s := range tc.statuses {
				addResult(m, "SV-1r1_rule", s)
			}
			if got := m["SV-1r1_rule"]; got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildTestResult(t *testing.T) {
	results := map[string]string{
		"SV-2r1_rule": statusFail,
		"SV-1r1_rule": statusPass,
	}
	doc := buildTestResult("stig", "ocp4-stig", results, "2026-09-01T00:00:00Z")

	if got := len(doc.RuleResults); got != 2 {
		t.Fatalf("expected 2 rule-results, got %d", got)
	}
	// Rule ids must be emitted in sorted order for stable output.
	if doc.RuleResults[0].IDRef != "SV-1r1_rule" || doc.RuleResults[1].IDRef != "SV-2r1_rule" {
		t.Fatalf("rule-results not sorted: %q, %q", doc.RuleResults[0].IDRef, doc.RuleResults[1].IDRef)
	}
	// One pass out of one pass+one fail -> 50%.
	if doc.Score.Value != "50.000000" {
		t.Fatalf("expected score 50.000000, got %q", doc.Score.Value)
	}

	out, err := marshalTestResult(doc)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	s := string(out)
	for _, want := range []string{
		`<?xml version="1.0" encoding="UTF-8"?>`,
		`<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2"`,
		`<rule-result idref="SV-1r1_rule"`,
		`<result>pass</result>`,
		`<result>fail</result>`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("marshaled output missing %q\n%s", want, s)
		}
	}
}

func TestStatusToXCCDFResult(t *testing.T) {
	cases := map[string]string{
		statusPass:          "pass",
		statusFail:          "fail",
		statusError:         "error",
		statusInfo:          "informational",
		statusManual:        "notchecked",
		statusNotApplicable: "notapplicable",
		statusInconsistent:  "error",
		"":                  "unknown",
	}
	for in, want := range cases {
		if got := statusToXCCDFResult(in); got != want {
			t.Errorf("statusToXCCDFResult(%q) = %q, want %q", in, got, want)
		}
	}
}
