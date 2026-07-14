package main

import (
	"os"
	"path/filepath"
	"testing"
)

// writeRule creates a temp rule dir with a cel/shared.yml and returns its path.
func writeRule(t *testing.T, sharedYml string) string {
	t.Helper()
	dir := t.TempDir()
	celDir := filepath.Join(dir, "cel")
	if err := os.MkdirAll(celDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(celDir, "shared.yml"), []byte(sharedYml), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const singleObjectRule = `
check_type: Platform
inputs:
  - name: hco
    kubernetes_input_spec:
      api_version: hco.kubevirt.io/v1beta1
      resource: hyperconvergeds
      resource_name: kubevirt-hyperconverged
      resource_namespace: openshift-cnv
expression: |
  has(hco.spec.featureGates) && hco.spec.featureGates.nonRoot == true
`

const listRuleWithItems = `
check_type: Platform
inputs:
  - name: vms
    kubernetes_input_spec:
      api_version: kubevirt.io/v1
      resource: virtualmachines
expression: |
  vms.items.all(v, !has(v.spec.broken) || v.spec.broken == false)
`

const listRuleMissingItems = `
check_type: Platform
inputs:
  - name: vms
    kubernetes_input_spec:
      api_version: kubevirt.io/v1
      resource: virtualmachines
expression: |
  vms.all(v, v.spec.broken == false)
`

const unguardedSingleObjectRule = `
check_type: Platform
inputs:
  - name: hco
    kubernetes_input_spec:
      api_version: hco.kubevirt.io/v1beta1
      resource: hyperconvergeds
      resource_name: kubevirt-hyperconverged
expression: |
  hco.spec.featureGates.nonRoot == true
`

// B1: --mock with a satisfied --expect false must exit 0.
func TestMockExpectFalseExitsZero(t *testing.T) {
	rule := writeRule(t, singleObjectRule)
	mock := writeFile(t, "hco.json", `{"spec":{"featureGates":{"nonRoot":false}}}`)
	if code := cacTest([]string{rule, "--mock", "hco=" + mock, "--expect", "false"}); code != 0 {
		t.Fatalf("satisfied --expect false: want exit 0, got %d", code)
	}
	if code := cacTest([]string{rule, "--mock", "hco=" + mock, "--expect", "true"}); code != 1 {
		t.Fatalf("unsatisfied --expect true: want exit 1, got %d", code)
	}
}

// B2: lint must pass a valid unguarded single-object rule (with a warning), and
// must fail a list rule iterated without .items.
func TestLintSingleObjectUnguardedPasses(t *testing.T) {
	rule := writeRule(t, unguardedSingleObjectRule)
	if code := cacLint([]string{rule}); code != 0 {
		t.Fatalf("unguarded single-object rule: want lint pass, got exit %d", code)
	}
}

func TestLintListWithoutItemsFails(t *testing.T) {
	rule := writeRule(t, listRuleMissingItems)
	if code := cacLint([]string{rule}); code != 1 {
		t.Fatalf("list rule without .items: want lint fail, got exit %d", code)
	}
}

func TestLintListWithItemsPasses(t *testing.T) {
	rule := writeRule(t, listRuleWithItems)
	if code := cacLint([]string{rule}); code != 0 {
		t.Fatalf("list rule with .items: want lint pass, got exit %d", code)
	}
}

// B3: a fixture referencing an unknown input name must fail the case.
func TestUnknownFixtureInputFails(t *testing.T) {
	rule := writeRule(t, singleObjectRule)
	cases := writeFile(t, "cases.yaml", `
- name: typo'd input
  expect: false
  inputs:
    hcolist:
      spec: {featureGates: {nonRoot: false}}
`)
	if code := cacTest([]string{rule, "--cases", cases}); code != 1 {
		t.Fatalf("typo'd fixture input: want exit 1, got %d", code)
	}
}

// F1: scanner semantics — a `no such key` eval error counts as FAIL (expect:
// false passes), matching the compliance-sdk scanner's special case.
func TestNoSuchKeyMapsToFail(t *testing.T) {
	rule := writeRule(t, listRuleMissingItems) // vms.all(...) over a List object -> no such key
	cases := writeFile(t, "cases.yaml", `
- name: scanner maps no-such-key to FAIL
  expect: false
  inputs:
    vms:
      items:
        - spec: {broken: false}
`)
	if code := cacTest([]string{rule, "--cases", cases}); code != 0 {
		t.Fatalf("no-such-key case expecting false: want exit 0, got %d", code)
	}
}

// F3 + binding semantics: list inputs get a full List wrapper; single-object
// inputs accept either the object or a wrapper.
func TestNormalizeBinding(t *testing.T) {
	listIn := cacInput{Name: "vms", Spec: cacInputSpec{Resource: "virtualmachines"}}
	obj := map[string]interface{}{"spec": map[string]interface{}{}}

	wrapped, ok := listIn.normalizeBinding([]interface{}{obj}).(map[string]interface{})
	if !ok || wrapped["kind"] != "List" || wrapped["apiVersion"] != "v1" {
		t.Fatalf("bare array should become a full List object, got %#v", wrapped)
	}
	if items, ok := wrapped["items"].([]interface{}); !ok || len(items) != 1 {
		t.Fatalf("items not preserved: %#v", wrapped)
	}

	singleIn := cacInput{Name: "hco", Spec: cacInputSpec{Resource: "hyperconvergeds", ResourceName: "x"}}
	if got := singleIn.normalizeBinding(obj); got == nil {
		t.Fatal("single object binding lost")
	}
	fromList := singleIn.normalizeBinding(map[string]interface{}{"items": []interface{}{obj}})
	if _, ok := fromList.(map[string]interface{}); !ok {
		t.Fatalf("single-object input should unwrap a List, got %#v", fromList)
	}
}

// End-to-end fixtures happy path: auto-discovery of cel/tests/*.yaml.
func TestFixtureAutoDiscovery(t *testing.T) {
	rule := writeRule(t, singleObjectRule)
	testsDir := filepath.Join(rule, "cel", "tests")
	if err := os.MkdirAll(testsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fixtures := `
- name: enabled -> compliant
  expect: true
  inputs:
    hco: {spec: {featureGates: {nonRoot: true}}}
- name: disabled -> non-compliant
  expect: false
  inputs:
    hco: {spec: {featureGates: {nonRoot: false}}}
- name: absent featureGates -> non-compliant (has() guard)
  expect: false
  inputs:
    hco: {spec: {}}
`
	if err := os.WriteFile(filepath.Join(testsDir, "cases.yaml"), []byte(fixtures), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := cacTest([]string{rule}); code != 0 {
		t.Fatalf("auto-discovered fixtures: want exit 0, got %d", code)
	}
}

// parseJSON/parseYAML parity with the scanner environment.
func TestParseJSONFunctionAvailable(t *testing.T) {
	got, err := evalExpr(`parseJSON(cfg).enabled == true`, map[string]interface{}{
		"cfg": `{"enabled": true}`,
	})
	if err != nil || !got {
		t.Fatalf("parseJSON: got=%v err=%v", got, err)
	}
	got, err = evalExpr(`parseYAML(cfg).enabled == true`, map[string]interface{}{
		"cfg": "enabled: true",
	})
	if err != nil || !got {
		t.Fatalf("parseYAML: got=%v err=%v", got, err)
	}
}
