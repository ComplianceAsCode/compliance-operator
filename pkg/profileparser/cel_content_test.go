package profileparser

import (
	"testing"

	cmpv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"sigs.k8s.io/yaml"
)

func TestCELBundleContentUnmarshal(t *testing.T) {
	yamlData := `
rules:
  - name: check-pods-running
    id: check_pods_running
    title: Check pods are running
    description: Ensures all pods are in running state
    severity: medium
    checkType: Platform
    expression: "pods.items.all(p, p.status.phase == 'Running')"
    inputs:
      - name: pods
        kubernetesInputSpec:
          apiVersion: v1
          resource: pods
    failureReason: "Some pods are not in Running state"
    variables:
      - var-pod-timeout
      - var-pod-grace-period
    controls:
      NIST-800-53:
        - "IA-5(f)"
        - "CM-6(a)"
      CIS-OCP:
        - "1.2.3"
profiles:
  - name: cel-platform-profile
    id: cel_profile_platform
    title: CEL Platform Profile
    description: Platform compliance checks using CEL
    productType: Platform
    rules:
      - check-pods-running
    values:
      - var-pod-timeout
`
	var bundle CELBundleContent
	if err := yaml.Unmarshal([]byte(yamlData), &bundle); err != nil {
		t.Fatalf("Failed to unmarshal CEL bundle: %v", err)
	}

	if len(bundle.Rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(bundle.Rules))
	}
	rule := bundle.Rules[0]
	if rule.Name != "check-pods-running" {
		t.Errorf("Expected rule name 'check-pods-running', got '%s'", rule.Name)
	}
	if rule.Expression != "pods.items.all(p, p.status.phase == 'Running')" {
		t.Errorf("Unexpected expression: %s", rule.Expression)
	}
	if len(rule.Inputs) != 1 {
		t.Fatalf("Expected 1 input, got %d", len(rule.Inputs))
	}
	if rule.Inputs[0].Name != "pods" {
		t.Errorf("Expected input name 'pods', got '%s'", rule.Inputs[0].Name)
	}
	if len(rule.Variables) != 2 {
		t.Fatalf("Expected 2 variables, got %d", len(rule.Variables))
	}
	if rule.Variables[0] != "var-pod-timeout" || rule.Variables[1] != "var-pod-grace-period" {
		t.Errorf("Unexpected variables: %v", rule.Variables)
	}
	if len(rule.Controls) != 2 {
		t.Fatalf("Expected 2 control standards, got %d", len(rule.Controls))
	}
	nistCtrls := rule.Controls["NIST-800-53"]
	if len(nistCtrls) != 2 || nistCtrls[0] != "IA-5(f)" || nistCtrls[1] != "CM-6(a)" {
		t.Errorf("Unexpected NIST controls: %v", nistCtrls)
	}
	cisCtrls := rule.Controls["CIS-OCP"]
	if len(cisCtrls) != 1 || cisCtrls[0] != "1.2.3" {
		t.Errorf("Unexpected CIS controls: %v", cisCtrls)
	}

	if len(bundle.Profiles) != 1 {
		t.Fatalf("Expected 1 profile, got %d", len(bundle.Profiles))
	}
	profile := bundle.Profiles[0]
	if profile.Name != "cel-platform-profile" {
		t.Errorf("Expected profile name 'cel-platform-profile', got '%s'", profile.Name)
	}
	if len(profile.Rules) != 1 {
		t.Fatalf("Expected 1 rule in profile, got %d", len(profile.Rules))
	}
	if profile.Rules[0] != "check-pods-running" {
		t.Errorf("Expected profile rule 'check-pods-running', got '%s'", profile.Rules[0])
	}
	if len(profile.Values) != 1 {
		t.Fatalf("Expected 1 value in profile, got %d", len(profile.Values))
	}
	if profile.Values[0] != "var-pod-timeout" {
		t.Errorf("Expected profile value 'var-pod-timeout', got '%s'", profile.Values[0])
	}
}

func TestCELBundleToRulePayload(t *testing.T) {
	celRule := CELRuleContent{
		Name:          "check-namespaces",
		ID:            "check_namespaces",
		Title:         "Check namespaces",
		Description:   "Verifies namespace configuration",
		Severity:      "high",
		CheckType:     "Platform",
		Expression:    "namespaces.items.size() > 0",
		FailureReason: "No namespaces found",
		Inputs: []cmpv1alpha1.InputPayload{
			{
				Name: "namespaces",
				KubernetesInputSpec: cmpv1alpha1.KubernetesInputSpec{
					APIVersion: "v1",
					Resource:   "namespaces",
				},
			},
		},
	}

	payload := cmpv1alpha1.RulePayload{
		ID:            celRule.ID,
		Title:         celRule.Title,
		Description:   celRule.Description,
		Severity:      celRule.Severity,
		CheckType:     celRule.CheckType,
		ScannerType:   cmpv1alpha1.ScannerTypeCEL,
		Expression:    celRule.Expression,
		Inputs:        celRule.Inputs,
		FailureReason: celRule.FailureReason,
	}

	if payload.ScannerType != cmpv1alpha1.ScannerTypeCEL {
		t.Errorf("Expected ScannerType CEL, got %s", payload.ScannerType)
	}
	if payload.Expression != "namespaces.items.size() > 0" {
		t.Errorf("Unexpected expression: %s", payload.Expression)
	}
	if len(payload.Inputs) != 1 {
		t.Fatalf("Expected 1 input, got %d", len(payload.Inputs))
	}
}
