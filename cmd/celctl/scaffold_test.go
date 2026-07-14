package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Offline scaffold: writes a wrapper-format fixtures file with provenance and
// TODO cases that loadCases can parse.
func TestScaffoldOffline(t *testing.T) {
	rule := writeRule(t, listRuleWithItems)
	if code := cacScaffold([]string{rule}); code != 0 {
		t.Fatalf("scaffold: want exit 0, got %d", code)
	}
	out := filepath.Join(rule, "cel", "tests", "cases.yaml")
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "provenance:") ||
		!strings.Contains(string(b), "offline skeleton") {
		t.Fatalf("scaffold output missing provenance:\n%s", b)
	}
	cases, err := loadCases(out)
	if err != nil {
		t.Fatalf("scaffolded file not loadable: %v", err)
	}
	// compliant + non-compliant + empty-list edge for the list input
	if len(cases) != 3 {
		t.Fatalf("want 3 scaffolded cases, got %d", len(cases))
	}
	// refuses to overwrite without --force
	if code := cacScaffold([]string{rule}); code == 0 {
		t.Fatal("scaffold over existing file: want failure without --force")
	}
	if code := cacScaffold([]string{rule, "--force"}); code != 0 {
		t.Fatal("scaffold --force: want success")
	}
}

// Wrapper and bare-list fixture formats both load.
func TestLoadCasesWrapperFormat(t *testing.T) {
	wrapper := writeFile(t, "wrapper.yaml", `
provenance:
  fetched_with: celctl cac scaffold --from-cluster
  date: "2026-07-12"
  openshift_version: 4.21.0
  source_api_versions: {hco: hco.kubevirt.io/v1beta1}
cases:
  - name: from wrapper
    expect: true
    inputs:
      hco: {spec: {featureGates: {nonRoot: true}}}
`)
	cases, err := loadCases(wrapper)
	if err != nil || len(cases) != 1 || cases[0].Name != "from wrapper" {
		t.Fatalf("wrapper format: cases=%v err=%v", cases, err)
	}

	bare := writeFile(t, "bare.yaml", `
- name: bare list
  expect: false
  inputs:
    hco: {spec: {}}
`)
	cases, err = loadCases(bare)
	if err != nil || len(cases) != 1 || cases[0].Name != "bare list" {
		t.Fatalf("bare-list format: cases=%v err=%v", cases, err)
	}
}

// Sanitizer strips server-managed noise but keeps the meaningful fields.
func TestSanitizeObject(t *testing.T) {
	obj := map[string]interface{}{
		"apiVersion": "hco.kubevirt.io/v1beta1",
		"metadata": map[string]interface{}{
			"name":              "kubevirt-hyperconverged",
			"namespace":         "openshift-cnv",
			"uid":               "abc-123",
			"resourceVersion":   "99",
			"generation":        int64(4),
			"creationTimestamp": "2026-01-01T00:00:00Z",
			"managedFields":     []interface{}{map[string]interface{}{"manager": "x"}},
			"annotations": map[string]interface{}{
				"kubectl.kubernetes.io/last-applied-configuration": "{...}",
				"deployOVS": "false",
			},
		},
		"spec": map[string]interface{}{"featureGates": map[string]interface{}{"nonRoot": true}},
		"status": map[string]interface{}{
			"relatedObjects": []interface{}{map[string]interface{}{
				"name": "x", "uid": "deadbeef", "resourceVersion": "42",
			}},
		},
	}
	got := sanitizeObject(obj, false).(map[string]interface{})
	if _, ok := got["status"]; ok {
		t.Fatal("status should be dropped by default")
	}
	md := got["metadata"].(map[string]interface{})
	for _, k := range []string{"uid", "resourceVersion", "generation", "creationTimestamp", "managedFields"} {
		if _, ok := md[k]; ok {
			t.Fatalf("sanitize left %q behind", k)
		}
	}
	if md["name"] != "kubevirt-hyperconverged" || md["namespace"] != "openshift-cnv" {
		t.Fatal("sanitize dropped name/namespace")
	}
	ann := md["annotations"].(map[string]interface{})
	if _, ok := ann["kubectl.kubernetes.io/last-applied-configuration"]; ok {
		t.Fatal("sanitize left last-applied annotation")
	}
	if ann["deployOVS"] != "false" {
		t.Fatal("sanitize dropped a real annotation")
	}
	if got["spec"].(map[string]interface{})["featureGates"] == nil {
		t.Fatal("sanitize dropped spec")
	}
	// keep-status: status retained but deep-stripped of uid/resourceVersion
	obj2 := map[string]interface{}{
		"status": map[string]interface{}{
			"relatedObjects": []interface{}{map[string]interface{}{
				"name": "x", "uid": "deadbeef", "resourceVersion": "42",
			}},
		},
	}
	kept := sanitizeObject(obj2, true).(map[string]interface{})
	ro := kept["status"].(map[string]interface{})["relatedObjects"].([]interface{})[0].(map[string]interface{})
	if _, ok := ro["uid"]; ok {
		t.Fatal("keep-status should deep-strip uid")
	}
	if ro["name"] != "x" {
		t.Fatal("keep-status dropped a real field")
	}
	// List form: items sanitized too
	list := map[string]interface{}{"items": []interface{}{obj}}
	slist := sanitizeObject(list, false).(map[string]interface{})
	item0 := slist["items"].([]interface{})[0].(map[string]interface{})
	if _, ok := item0["metadata"].(map[string]interface{})["uid"]; ok {
		t.Fatal("sanitize skipped List items")
	}
}

// A scaffolded-then-filled fixture round-trips through cac test.
func TestScaffoldFillTestRoundTrip(t *testing.T) {
	rule := writeRule(t, singleObjectRule)
	if code := cacScaffold([]string{rule}); code != 0 {
		t.Fatal("scaffold failed")
	}
	out := filepath.Join(rule, "cel", "tests", "cases.yaml")
	ff := fixtureFile{
		Provenance: &fixtureProvenance{FetchedWith: "test", Date: "2026-07-12"},
		Cases: []cacCase{
			{Name: "enabled", Expect: true,
				Inputs: map[string]interface{}{"hco": map[string]interface{}{
					"spec": map[string]interface{}{"featureGates": map[string]interface{}{"nonRoot": true}}}}},
			{Name: "absent gates", Expect: false,
				Inputs: map[string]interface{}{"hco": map[string]interface{}{
					"spec": map[string]interface{}{}}}},
		},
	}
	b, _ := yaml.Marshal(&ff)
	if err := os.WriteFile(out, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if code := cacTest([]string{rule}); code != 0 {
		t.Fatal("filled scaffolded fixture should pass cac test")
	}
}
