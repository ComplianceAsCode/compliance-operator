package celcontent

import (
	"os"
	"path/filepath"
	"testing"

	"sigs.k8s.io/yaml"
)

const (
	testRulesDir    = "../../tests/data/cel-rules"
	testProfilesDir = "../../tests/data/cel-profiles"
)

func TestBundleFromDirs(t *testing.T) {
	bundle, err := BundleFromDirs(testRulesDir, testProfilesDir)
	if err != nil {
		t.Fatalf("BundleFromDirs failed: %v", err)
	}

	if len(bundle.Rules) != 3 {
		t.Fatalf("Expected 3 rules, got %d", len(bundle.Rules))
	}

	// Rules are sorted by name
	expectedNames := []string{
		"check-default-namespace-has-no-pods",
		"check-namespaces-have-network-policies",
		"check-no-privileged-containers",
	}
	for i, want := range expectedNames {
		if bundle.Rules[i].Name != want {
			t.Errorf("Rule[%d] name = %q, want %q", i, bundle.Rules[i].Name, want)
		}
	}

	if len(bundle.Profiles) != 1 {
		t.Fatalf("Expected 1 profile, got %d", len(bundle.Profiles))
	}
	if bundle.Profiles[0].Name != "cel-e2e-test-profile" {
		t.Errorf("Profile name = %q, want %q", bundle.Profiles[0].Name, "cel-e2e-test-profile")
	}
	if len(bundle.Profiles[0].Rules) != 3 {
		t.Errorf("Profile rules count = %d, want 3", len(bundle.Profiles[0].Rules))
	}
}

func TestBundleFromDirs_RuleFields(t *testing.T) {
	bundle, err := BundleFromDirs(testRulesDir, testProfilesDir)
	if err != nil {
		t.Fatalf("BundleFromDirs failed: %v", err)
	}

	ruleMap := make(map[string]CELRuleContent)
	for _, r := range bundle.Rules {
		ruleMap[r.Name] = r
	}

	t.Run("check-default-namespace-has-no-pods", func(t *testing.T) {
		r := ruleMap["check-default-namespace-has-no-pods"]
		if r.ID != "check_default_namespace_has_no_pods" {
			t.Errorf("ID = %q", r.ID)
		}
		if r.Severity != "medium" {
			t.Errorf("Severity = %q", r.Severity)
		}
		if len(r.Inputs) != 1 {
			t.Fatalf("Inputs count = %d, want 1", len(r.Inputs))
		}
		if r.Inputs[0].Name != "pods" {
			t.Errorf("Input name = %q", r.Inputs[0].Name)
		}
		if r.Inputs[0].KubernetesInputSpec.ResourceNamespace != "default" {
			t.Errorf("Input namespace = %q", r.Inputs[0].KubernetesInputSpec.ResourceNamespace)
		}
		if len(r.Controls["NIST-800-53"]) != 2 {
			t.Errorf("NIST controls = %d", len(r.Controls["NIST-800-53"]))
		}
		if len(r.Controls["CIS-OCP"]) != 1 {
			t.Errorf("CIS controls = %d", len(r.Controls["CIS-OCP"]))
		}
	})

	t.Run("check-namespaces-have-network-policies", func(t *testing.T) {
		r := ruleMap["check-namespaces-have-network-policies"]
		if len(r.Inputs) != 2 {
			t.Fatalf("Inputs count = %d, want 2", len(r.Inputs))
		}
		if r.Inputs[0].Name != "namespaces" || r.Inputs[1].Name != "networkpolicies" {
			t.Errorf("Input names = %q, %q", r.Inputs[0].Name, r.Inputs[1].Name)
		}
		if r.Inputs[1].KubernetesInputSpec.Group != "networking.k8s.io" {
			t.Errorf("Input group = %q", r.Inputs[1].KubernetesInputSpec.Group)
		}
	})

	t.Run("check-no-privileged-containers", func(t *testing.T) {
		r := ruleMap["check-no-privileged-containers"]
		if r.Severity != "high" {
			t.Errorf("Severity = %q", r.Severity)
		}
		if len(r.Inputs) != 1 || r.Inputs[0].Name != "pods" {
			t.Errorf("Inputs: %v", r.Inputs)
		}
	})
}

func TestBundleToYAML_Roundtrip(t *testing.T) {
	bundle, err := BundleFromDirs(testRulesDir, testProfilesDir)
	if err != nil {
		t.Fatalf("BundleFromDirs failed: %v", err)
	}

	data, err := BundleToYAML(bundle)
	if err != nil {
		t.Fatalf("BundleToYAML failed: %v", err)
	}

	var roundtripped CELBundleContent
	if err := yaml.Unmarshal(data, &roundtripped); err != nil {
		t.Fatalf("Roundtrip unmarshal failed: %v", err)
	}

	if len(roundtripped.Rules) != len(bundle.Rules) {
		t.Errorf("Roundtrip rules: got %d, want %d", len(roundtripped.Rules), len(bundle.Rules))
	}
	if len(roundtripped.Profiles) != len(bundle.Profiles) {
		t.Errorf("Roundtrip profiles: got %d, want %d", len(roundtripped.Profiles), len(bundle.Profiles))
	}

	for i, r := range roundtripped.Rules {
		if r.Name != bundle.Rules[i].Name {
			t.Errorf("Roundtrip rule[%d] name: got %q, want %q", i, r.Name, bundle.Rules[i].Name)
		}
		if r.Expression != bundle.Rules[i].Expression {
			t.Errorf("Roundtrip rule[%d] expression mismatch", i)
		}
	}
}

func TestBundleToFile(t *testing.T) {
	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "cel-bundle.yaml")

	err := BundleToFile(testRulesDir, testProfilesDir, outPath)
	if err != nil {
		t.Fatalf("BundleToFile failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("Reading output file failed: %v", err)
	}

	var bundle CELBundleContent
	if err := yaml.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("Unmarshaling output failed: %v", err)
	}

	if len(bundle.Rules) != 3 {
		t.Errorf("Output rules = %d, want 3", len(bundle.Rules))
	}
	if len(bundle.Profiles) != 1 {
		t.Errorf("Output profiles = %d, want 1", len(bundle.Profiles))
	}
}

func TestBundleFromDirs_DuplicateRuleName(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	profilesDir := filepath.Join(dir, "profiles")
	os.MkdirAll(rulesDir, 0755)
	os.MkdirAll(profilesDir, 0755)

	ruleYAML := `name: dup-rule
id: dup_rule
title: Dup
severity: medium
checkType: Platform
expression: "x.items.size() > 0"
inputs:
  - name: x
    kubernetesInputSpec:
      apiVersion: v1
      resource: pods
`
	os.WriteFile(filepath.Join(rulesDir, "a.yaml"), []byte(ruleYAML), 0644)
	os.WriteFile(filepath.Join(rulesDir, "b.yaml"), []byte(ruleYAML), 0644)

	profileYAML := `name: p
id: p_id
title: P
rules:
  - dup-rule
`
	os.WriteFile(filepath.Join(profilesDir, "p.yaml"), []byte(profileYAML), 0644)

	_, err := BundleFromDirs(rulesDir, profilesDir)
	if err == nil {
		t.Fatal("Expected error for duplicate rule names")
	}
	if got := err.Error(); !contains(got, "duplicate rule name") {
		t.Errorf("Error = %q, want to contain 'duplicate rule name'", got)
	}
}

func TestBundleFromDirs_UnknownRuleRef(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	profilesDir := filepath.Join(dir, "profiles")
	os.MkdirAll(rulesDir, 0755)
	os.MkdirAll(profilesDir, 0755)

	ruleYAML := `name: real-rule
id: real_rule
title: Real
severity: medium
checkType: Platform
expression: "x.items.size() > 0"
inputs:
  - name: x
    kubernetesInputSpec:
      apiVersion: v1
      resource: pods
`
	os.WriteFile(filepath.Join(rulesDir, "real.yaml"), []byte(ruleYAML), 0644)

	profileYAML := `name: p
id: p_id
title: P
rules:
  - real-rule
  - ghost-rule
`
	os.WriteFile(filepath.Join(profilesDir, "p.yaml"), []byte(profileYAML), 0644)

	_, err := BundleFromDirs(rulesDir, profilesDir)
	if err == nil {
		t.Fatal("Expected error for unknown rule reference")
	}
	if got := err.Error(); !contains(got, "unknown rule") {
		t.Errorf("Error = %q, want to contain 'unknown rule'", got)
	}
}

func TestBundleFromDirs_MissingFields(t *testing.T) {
	tests := []struct {
		name     string
		ruleYAML string
		errMsg   string
	}{
		{
			name:     "no name",
			ruleYAML: `{id: x, severity: medium, checkType: Platform, expression: "true", inputs: [{name: x, kubernetesInputSpec: {apiVersion: v1, resource: pods}}]}`,
			errMsg:   "has no name",
		},
		{
			name:     "no expression",
			ruleYAML: `{name: x, id: x, severity: medium, checkType: Platform, inputs: [{name: x, kubernetesInputSpec: {apiVersion: v1, resource: pods}}]}`,
			errMsg:   "has no expression",
		},
		{
			name:     "no inputs",
			ruleYAML: `{name: x, id: x, severity: medium, checkType: Platform, expression: "true"}`,
			errMsg:   "has no inputs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			rulesDir := filepath.Join(dir, "rules")
			profilesDir := filepath.Join(dir, "profiles")
			os.MkdirAll(rulesDir, 0755)
			os.MkdirAll(profilesDir, 0755)
			os.WriteFile(filepath.Join(rulesDir, "r.yaml"), []byte(tt.ruleYAML), 0644)

			_, err := BundleFromDirs(rulesDir, profilesDir)
			if err == nil {
				t.Fatal("Expected error")
			}
			if !contains(err.Error(), tt.errMsg) {
				t.Errorf("Error = %q, want to contain %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestBundleFromDirs_EmptyProfile(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	profilesDir := filepath.Join(dir, "profiles")
	os.MkdirAll(rulesDir, 0755)
	os.MkdirAll(profilesDir, 0755)

	ruleYAML := `name: r
id: r_id
title: R
severity: medium
checkType: Platform
expression: "true"
inputs:
  - name: x
    kubernetesInputSpec:
      apiVersion: v1
      resource: pods
`
	os.WriteFile(filepath.Join(rulesDir, "r.yaml"), []byte(ruleYAML), 0644)

	profileYAML := `name: empty-profile
id: empty
title: Empty
`
	os.WriteFile(filepath.Join(profilesDir, "p.yaml"), []byte(profileYAML), 0644)

	_, err := BundleFromDirs(rulesDir, profilesDir)
	if err == nil {
		t.Fatal("Expected error for profile with no rules")
	}
	if !contains(err.Error(), "has no rules") {
		t.Errorf("Error = %q, want to contain 'has no rules'", err.Error())
	}
}

func TestBundleFromDirs_NonYAMLIgnored(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	profilesDir := filepath.Join(dir, "profiles")
	os.MkdirAll(rulesDir, 0755)
	os.MkdirAll(profilesDir, 0755)

	ruleYAML := `name: r
id: r_id
title: R
severity: medium
checkType: Platform
expression: "x.items.size() > 0"
inputs:
  - name: x
    kubernetesInputSpec:
      apiVersion: v1
      resource: pods
`
	os.WriteFile(filepath.Join(rulesDir, "r.yaml"), []byte(ruleYAML), 0644)
	os.WriteFile(filepath.Join(rulesDir, "README.md"), []byte("# ignore me"), 0644)

	profileYAML := `name: p
id: p_id
title: P
rules:
  - r
`
	os.WriteFile(filepath.Join(profilesDir, "p.yaml"), []byte(profileYAML), 0644)
	os.WriteFile(filepath.Join(profilesDir, ".gitkeep"), []byte(""), 0644)

	bundle, err := BundleFromDirs(rulesDir, profilesDir)
	if err != nil {
		t.Fatalf("BundleFromDirs failed: %v", err)
	}
	if len(bundle.Rules) != 1 {
		t.Errorf("Rules = %d, want 1 (non-YAML should be ignored)", len(bundle.Rules))
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
