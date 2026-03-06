package profileparser

import (
	"context"
	"os"
	"testing"

	cmpv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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

var _ = Describe("ParseCELBundle integration", func() {
	const celYAML = `rules:
  - name: check-nodes
    id: check_nodes
    title: Check nodes exist
    severity: medium
    checkType: Platform
    expression: "nodes.items.size() > 0"
    inputs:
      - name: nodes
        kubernetesInputSpec:
          apiVersion: v1
          resource: nodes
    failureReason: "No nodes found"
    variables:
      - var-min-nodes
    controls:
      NIST-800-53:
        - "CM-6(a)"
        - "IA-5(f)"
      CIS-OCP:
        - "1.1.1"
profiles:
  - name: cel-nodes-profile
    id: cel_profile_nodes
    title: CEL Nodes Profile
    productType: Platform
    rules:
      - check-nodes
    values:
      - var-min-nodes
`

	It("creates Rule and Profile CRs with correct annotations", func() {
		tmpFile, err := os.CreateTemp("", "cel-bundle-*.yaml")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString(celYAML)
		Expect(err).NotTo(HaveOccurred())
		Expect(tmpFile.Close()).To(Succeed())

		pb := &cmpv1alpha1.ProfileBundle{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cel-test-pb",
				Namespace: testNamespace,
			},
		}
		Expect(client.Create(context.TODO(), pb)).To(Succeed())

		pcfg := &ParserConfig{
			Client: client,
			Scheme: client.Scheme(),
		}

		err = ParseCELBundle(tmpFile.Name(), pb, pcfg)
		Expect(err).NotTo(HaveOccurred())

		// Verify Rule CR
		rule := &cmpv1alpha1.Rule{}
		ruleKey := types.NamespacedName{
			Name:      GetPrefixedName(pb.Name, "check-nodes"),
			Namespace: testNamespace,
		}
		Expect(client.Get(context.TODO(), ruleKey, rule)).To(Succeed())
		Expect(rule.RulePayload.ScannerType).To(Equal(cmpv1alpha1.ScannerTypeCEL))
		Expect(rule.RulePayload.Expression).To(Equal("nodes.items.size() > 0"))
		Expect(rule.RulePayload.Inputs).To(HaveLen(1))
		Expect(rule.RulePayload.FailureReason).To(Equal("No nodes found"))
		Expect(rule.Annotations[cmpv1alpha1.RuleIDAnnotationKey]).To(Equal("check-nodes"))
		Expect(rule.Annotations[cmpv1alpha1.RuleVariableAnnotationKey]).To(Equal("var-min-nodes"))

		nistKey := "control.compliance.openshift.io/NIST-800-53"
		Expect(rule.Annotations).To(HaveKey(nistKey))
		Expect(rule.Annotations[nistKey]).To(ContainSubstring("CM-6(a)"))
		Expect(rule.Annotations[nistKey]).To(ContainSubstring("IA-5(f)"))

		cisKey := "control.compliance.openshift.io/CIS-OCP"
		Expect(rule.Annotations[cisKey]).To(Equal("1.1.1"))

		Expect(rule.Annotations["policies.open-cluster-management.io/standards"]).To(ContainSubstring("NIST-800-53"))
		Expect(rule.Annotations["policies.open-cluster-management.io/standards"]).To(ContainSubstring("CIS-OCP"))

		profileRefAnnotation := rule.Annotations[cmpv1alpha1.RuleProfileAnnotationKey]
		Expect(profileRefAnnotation).To(ContainSubstring(GetPrefixedName(pb.Name, "cel-nodes-profile")))

		// Verify Profile CR
		profile := &cmpv1alpha1.Profile{}
		profileKey := types.NamespacedName{
			Name:      GetPrefixedName(pb.Name, "cel-nodes-profile"),
			Namespace: testNamespace,
		}
		Expect(client.Get(context.TODO(), profileKey, profile)).To(Succeed())
		Expect(profile.Annotations[cmpv1alpha1.ScannerTypeAnnotation]).To(Equal(string(cmpv1alpha1.ScannerTypeCEL)))
		Expect(profile.Annotations[cmpv1alpha1.ProductTypeAnnotation]).To(Equal("Platform"))
		Expect(profile.Labels).To(HaveKey(cmpv1alpha1.ProfileGuidLabel))
		Expect(profile.Labels[cmpv1alpha1.ProfileBundleOwnerLabel]).To(Equal(pb.Name))
		Expect(profile.ID).To(Equal("cel_profile_nodes"))
		Expect(profile.Title).To(Equal("CEL Nodes Profile"))
		Expect(profile.Rules).To(HaveLen(1))
		Expect(string(profile.Rules[0])).To(Equal(GetPrefixedName(pb.Name, "check-nodes")))
		Expect(profile.Values).To(HaveLen(1))
		Expect(string(profile.Values[0])).To(Equal("var-min-nodes"))
	})
})
