package profileparser

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	cmpv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/celcontent"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils/celvalidation"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"
)

const (
	celTestRulesDir    = "../../tests/data/cel-rules"
	celTestProfilesDir = "../../tests/data/cel-profiles"
	celTestDataPath    = "../../tests/data/cel-content-test.yaml"
)

// generateCELBundleFile uses the bundler utility to assemble individual
// rule/profile files from tests/data into a single bundle YAML. This exercises
// the full pipeline: individual files -> bundler -> bundle YAML.
func generateCELBundleFile(t *testing.T) string {
	t.Helper()
	outPath := filepath.Join(t.TempDir(), "cel-bundle.yaml")
	if err := celcontent.BundleToFile(celTestRulesDir, celTestProfilesDir, outPath); err != nil {
		t.Fatalf("Failed to generate CEL bundle from dirs: %v", err)
	}
	return outPath
}

func TestCELBundleContentUnmarshalFromBundler(t *testing.T) {
	bundlePath := generateCELBundleFile(t)
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("Failed to read generated CEL bundle: %v", err)
	}

	var bundle CELBundleContent
	if err := yaml.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("Failed to unmarshal CEL bundle: %v", err)
	}

	if len(bundle.Rules) != 4 {
		t.Fatalf("Expected 4 rules, got %d", len(bundle.Rules))
	}

	// Rules are sorted alphabetically by the bundler
	ruleMap := make(map[string]CELRuleContent, len(bundle.Rules))
	for _, r := range bundle.Rules {
		ruleMap[r.Name] = r
	}

	// check-default-namespace-has-no-pods
	r := ruleMap["check-default-namespace-has-no-pods"]
	if r.ID != "check_default_namespace_has_no_pods" {
		t.Errorf("rule id = %q", r.ID)
	}
	if r.Severity != "medium" {
		t.Errorf("severity = %q", r.Severity)
	}
	if len(r.Inputs) != 1 || r.Inputs[0].Name != "pods" {
		t.Errorf("inputs: %v", r.Inputs)
	}
	if r.Inputs[0].KubernetesInputSpec.ResourceNamespace != "default" {
		t.Errorf("input namespace = %q", r.Inputs[0].KubernetesInputSpec.ResourceNamespace)
	}
	if len(r.Controls["NIST-800-53"]) != 2 || len(r.Controls["CIS-OCP"]) != 1 {
		t.Errorf("controls: %v", r.Controls)
	}

	// check-default-sa-exists-in-kube-system
	r = ruleMap["check-default-sa-exists-in-kube-system"]
	if r.ID != "check_default_sa_exists_in_kube_system" {
		t.Errorf("rule id = %q", r.ID)
	}
	if r.Severity != "medium" {
		t.Errorf("severity = %q", r.Severity)
	}
	if len(r.Inputs) != 1 || r.Inputs[0].Name != "serviceaccounts" {
		t.Errorf("inputs: %v", r.Inputs)
	}
	if r.Inputs[0].KubernetesInputSpec.ResourceNamespace != "kube-system" {
		t.Errorf("input namespace = %q", r.Inputs[0].KubernetesInputSpec.ResourceNamespace)
	}
	if len(r.Controls["NIST-800-53"]) != 1 || len(r.Controls["CIS-OCP"]) != 1 {
		t.Errorf("controls: %v", r.Controls)
	}

	// check-namespaces-have-network-policies
	r = ruleMap["check-namespaces-have-network-policies"]
	if r.ID != "check_namespaces_have_network_policies" {
		t.Errorf("rule id = %q", r.ID)
	}
	if len(r.Inputs) != 2 {
		t.Errorf("inputs count = %d, want 2", len(r.Inputs))
	}
	if r.Inputs[0].Name != "namespaces" || r.Inputs[1].Name != "networkpolicies" {
		t.Errorf("input names = %q, %q", r.Inputs[0].Name, r.Inputs[1].Name)
	}
	if r.Inputs[1].KubernetesInputSpec.Group != "networking.k8s.io" {
		t.Errorf("input group = %q", r.Inputs[1].KubernetesInputSpec.Group)
	}

	// check-no-privileged-containers
	r = ruleMap["check-no-privileged-containers"]
	if r.ID != "check_no_privileged_containers" {
		t.Errorf("rule id = %q", r.ID)
	}
	if r.Severity != "high" {
		t.Errorf("severity = %q", r.Severity)
	}
	if len(r.Inputs) != 1 || r.Inputs[0].Name != "pods" {
		t.Errorf("inputs: %v", r.Inputs)
	}

	// Profile
	if len(bundle.Profiles) != 1 {
		t.Fatalf("Expected 1 profile, got %d", len(bundle.Profiles))
	}
	p := bundle.Profiles[0]
	if p.Name != "cel-e2e-test-profile" {
		t.Errorf("profile name = %q", p.Name)
	}
	if p.ID != "cel_e2e_test_profile" {
		t.Errorf("profile id = %q", p.ID)
	}
	if p.ProductType != "Platform" {
		t.Errorf("productType = %q", p.ProductType)
	}
	if len(p.Rules) != 4 {
		t.Fatalf("profile rules count = %d, want 4", len(p.Rules))
	}
}

func TestCELBundleCommittedFileMatchesBundler(t *testing.T) {
	bundlePath := generateCELBundleFile(t)

	generatedData, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("Failed to read generated bundle: %v", err)
	}
	committedData, err := os.ReadFile(celTestDataPath)
	if err != nil {
		t.Fatalf("Failed to read committed bundle: %v", err)
	}

	var generated, committed CELBundleContent
	if err := yaml.Unmarshal(generatedData, &generated); err != nil {
		t.Fatalf("unmarshal generated: %v", err)
	}
	if err := yaml.Unmarshal(committedData, &committed); err != nil {
		t.Fatalf("unmarshal committed: %v", err)
	}

	if len(generated.Rules) != len(committed.Rules) {
		t.Errorf("Rule count: generated=%d, committed=%d", len(generated.Rules), len(committed.Rules))
	}
	if len(generated.Profiles) != len(committed.Profiles) {
		t.Errorf("Profile count: generated=%d, committed=%d", len(generated.Profiles), len(committed.Profiles))
	}

	genRuleNames := make(map[string]bool)
	for _, r := range generated.Rules {
		genRuleNames[r.Name] = true
	}
	comRuleNames := make(map[string]bool)
	for _, r := range committed.Rules {
		comRuleNames[r.Name] = true
	}
	for name := range comRuleNames {
		if !genRuleNames[name] {
			t.Errorf("Committed rule %q not found in bundler output", name)
		}
	}
	for name := range genRuleNames {
		if !comRuleNames[name] {
			t.Errorf("Generated rule %q not found in committed file", name)
		}
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

func TestCELBundleCISVMExtension(t *testing.T) {
	data, err := os.ReadFile("../../tests/data/cel-cis-vm-extension-bundle.yaml")
	if err != nil {
		t.Fatalf("Failed to read CIS VM bundle: %v", err)
	}

	var bundle CELBundleContent
	if err := yaml.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("Failed to unmarshal CIS VM bundle: %v", err)
	}

	// --- Profile-level checks ---
	if len(bundle.Profiles) != 1 {
		t.Fatalf("Expected 1 profile, got %d", len(bundle.Profiles))
	}
	profile := bundle.Profiles[0]
	if profile.Name != "cis-vm-extension" {
		t.Errorf("profile name = %q, want cis-vm-extension", profile.Name)
	}
	if profile.ID != "cis-vm-extension" {
		t.Errorf("profile id = %q, want cis-vm-extension", profile.ID)
	}
	if profile.ProductType != "Platform" {
		t.Errorf("profile productType = %q, want Platform", profile.ProductType)
	}
	if profile.Title == "" {
		t.Error("profile title is empty")
	}
	if profile.Description == "" {
		t.Error("profile description is empty")
	}

	// --- Rule count and profile references ---
	expectedRules := []string{
		"kubevirt-enforce-trusted-tls-registries",
		"kubevirt-no-permitted-host-devices",
		"kubevirt-no-vms-overcommitting-guest-memory",
		"kubevirt-nonroot-feature-gate-is-enabled",
		"kubevirt-persistent-reservation-disabled",
	}
	if len(bundle.Rules) != len(expectedRules) {
		t.Fatalf("Expected %d rules, got %d", len(expectedRules), len(bundle.Rules))
	}
	if len(profile.Rules) != len(expectedRules) {
		t.Fatalf("Profile references %d rules, expected %d", len(profile.Rules), len(expectedRules))
	}

	ruleMap := make(map[string]CELRuleContent, len(bundle.Rules))
	for _, r := range bundle.Rules {
		ruleMap[r.Name] = r
	}
	for _, name := range expectedRules {
		if _, ok := ruleMap[name]; !ok {
			t.Errorf("expected rule %q not found in bundle", name)
		}
	}
	for _, name := range profile.Rules {
		if _, ok := ruleMap[name]; !ok {
			t.Errorf("profile references rule %q not found in bundle rules", name)
		}
	}

	// --- Detailed per-rule validation ---
	type ruleExpect struct {
		id, severity, checkType string
		inputName, apiVersion   string
		hasResourceName         bool
		hasResourceNamespace    bool
	}
	ruleExpects := map[string]ruleExpect{
		"kubevirt-enforce-trusted-tls-registries": {
			id: "kubevirt-enforce-trusted-tls-registries", severity: "medium", checkType: "Platform",
			inputName: "hco", apiVersion: "hco.kubevirt.io/v1beta1",
			hasResourceName: true, hasResourceNamespace: true,
		},
		"kubevirt-no-permitted-host-devices": {
			id: "kubevirt-no-permitted-host-devices", severity: "medium", checkType: "Platform",
			inputName: "hcoList", apiVersion: "hco.kubevirt.io/v1beta1",
		},
		"kubevirt-no-vms-overcommitting-guest-memory": {
			id: "kubevirt-no-vms-overcommitting-guest-memory", severity: "medium", checkType: "Platform",
			inputName: "vms", apiVersion: "kubevirt.io/v1",
		},
		"kubevirt-nonroot-feature-gate-is-enabled": {
			id: "kubevirt-nonroot-feature-gate-is-enabled", severity: "medium", checkType: "Platform",
			inputName: "hcoList", apiVersion: "hco.kubevirt.io/v1beta1",
		},
		"kubevirt-persistent-reservation-disabled": {
			id: "kubevirt-persistent-reservation-disabled", severity: "medium", checkType: "Platform",
			inputName: "hcoList", apiVersion: "hco.kubevirt.io/v1beta1",
		},
	}

	for name, exp := range ruleExpects {
		r := ruleMap[name]
		if r.ID != exp.id {
			t.Errorf("[%s] id = %q, want %q", name, r.ID, exp.id)
		}
		if r.Severity != exp.severity {
			t.Errorf("[%s] severity = %q, want %q", name, r.Severity, exp.severity)
		}
		if r.CheckType != exp.checkType {
			t.Errorf("[%s] checkType = %q, want %q", name, r.CheckType, exp.checkType)
		}
		if r.Title == "" {
			t.Errorf("[%s] title is empty", name)
		}
		if r.Description == "" {
			t.Errorf("[%s] description is empty", name)
		}
		if r.Rationale == "" {
			t.Errorf("[%s] rationale is empty", name)
		}
		if r.Expression == "" {
			t.Errorf("[%s] expression is empty", name)
		}
		if r.FailureReason == "" {
			t.Errorf("[%s] failureReason is empty", name)
		}
		if r.Instructions == "" {
			t.Errorf("[%s] instructions is empty", name)
		}
		if len(r.Inputs) != 1 {
			t.Errorf("[%s] expected 1 input, got %d", name, len(r.Inputs))
			continue
		}
		if r.Inputs[0].Name != exp.inputName {
			t.Errorf("[%s] input name = %q, want %q", name, r.Inputs[0].Name, exp.inputName)
		}
		if r.Inputs[0].KubernetesInputSpec.APIVersion != exp.apiVersion {
			t.Errorf("[%s] apiVersion = %q, want %q", name, r.Inputs[0].KubernetesInputSpec.APIVersion, exp.apiVersion)
		}
		if exp.hasResourceName && r.Inputs[0].KubernetesInputSpec.ResourceName == "" {
			t.Errorf("[%s] expected resourceName to be set", name)
		}
		if exp.hasResourceNamespace && r.Inputs[0].KubernetesInputSpec.ResourceNamespace == "" {
			t.Errorf("[%s] expected resourceNamespace to be set", name)
		}
	}

	// --- Validate all CEL expressions compile ---
	for _, rule := range bundle.Rules {
		payload := cmpv1alpha1.RulePayload{
			Expression: rule.Expression,
			Inputs:     rule.Inputs,
		}
		if err := celvalidation.ValidateCELRule(rule.Name, &payload); err != nil {
			t.Errorf("CEL validation failed for rule %q: %v", rule.Name, err)
		}
	}
}

var _ = Describe("ParseCELBundle integration", func() {
	const pbName = "cel-e2e-pb"

	It("creates Rule and Profile CRs from bundler-generated file", func() {
		outPath := filepath.Join(GinkgoT().TempDir(), "cel-bundle.yaml")
		Expect(celcontent.BundleToFile(celTestRulesDir, celTestProfilesDir, outPath)).To(Succeed())

		pb := &cmpv1alpha1.ProfileBundle{
			ObjectMeta: metav1.ObjectMeta{
				Name:      pbName,
				Namespace: testNamespace,
			},
		}
		Expect(client.Create(context.TODO(), pb)).To(Succeed())

		pcfg := &ParserConfig{
			Client: client,
			Scheme: client.Scheme(),
		}

		err := ParseCELBundle(outPath, pb, pcfg)
		Expect(err).NotTo(HaveOccurred())

		// --- Rule 1: check-default-namespace-has-no-pods ---
		rule1 := &cmpv1alpha1.Rule{}
		Expect(client.Get(context.TODO(), types.NamespacedName{
			Name:      GetPrefixedName(pbName, "check-default-namespace-has-no-pods"),
			Namespace: testNamespace,
		}, rule1)).To(Succeed())

		Expect(rule1.RulePayload.ScannerType).To(Equal(cmpv1alpha1.ScannerTypeCEL))
		Expect(rule1.RulePayload.ID).To(Equal("check_default_namespace_has_no_pods"))
		Expect(rule1.RulePayload.Severity).To(Equal("medium"))
		Expect(rule1.RulePayload.Inputs).To(HaveLen(1))
		Expect(rule1.RulePayload.Inputs[0].Name).To(Equal("pods"))
		Expect(rule1.RulePayload.Inputs[0].KubernetesInputSpec.ResourceNamespace).To(Equal("default"))
		Expect(rule1.RulePayload.FailureReason).To(ContainSubstring("default namespace"))
		Expect(rule1.RulePayload.Instructions).To(ContainSubstring("oc get pods"))
		Expect(rule1.RulePayload.Rationale).To(ContainSubstring("namespace-based"))

		Expect(rule1.Annotations[cmpv1alpha1.RuleIDAnnotationKey]).To(Equal("check-default-namespace-has-no-pods"))
		Expect(rule1.Annotations["control.compliance.openshift.io/NIST-800-53"]).To(ContainSubstring("AC-6"))
		Expect(rule1.Annotations["control.compliance.openshift.io/NIST-800-53"]).To(ContainSubstring("CM-7"))
		Expect(rule1.Annotations["control.compliance.openshift.io/CIS-OCP"]).To(Equal("5.7.4"))
		Expect(rule1.Annotations["policies.open-cluster-management.io/standards"]).To(ContainSubstring("NIST-800-53"))
		Expect(rule1.Annotations["policies.open-cluster-management.io/standards"]).To(ContainSubstring("CIS-OCP"))

		profileRef1 := rule1.Annotations[cmpv1alpha1.RuleProfileAnnotationKey]
		Expect(profileRef1).To(ContainSubstring(GetPrefixedName(pbName, "cel-e2e-test-profile")))

		// --- Rule 2: check-default-sa-exists-in-kube-system ---
		rule2 := &cmpv1alpha1.Rule{}
		Expect(client.Get(context.TODO(), types.NamespacedName{
			Name:      GetPrefixedName(pbName, "check-default-sa-exists-in-kube-system"),
			Namespace: testNamespace,
		}, rule2)).To(Succeed())

		Expect(rule2.RulePayload.ScannerType).To(Equal(cmpv1alpha1.ScannerTypeCEL))
		Expect(rule2.RulePayload.ID).To(Equal("check_default_sa_exists_in_kube_system"))
		Expect(rule2.RulePayload.Severity).To(Equal("medium"))
		Expect(rule2.RulePayload.Inputs).To(HaveLen(1))
		Expect(rule2.RulePayload.Inputs[0].Name).To(Equal("serviceaccounts"))
		Expect(rule2.RulePayload.Inputs[0].KubernetesInputSpec.ResourceNamespace).To(Equal("kube-system"))
		Expect(rule2.RulePayload.FailureReason).To(ContainSubstring("default ServiceAccount"))
		Expect(rule2.Annotations["control.compliance.openshift.io/NIST-800-53"]).To(ContainSubstring("CM-6"))
		Expect(rule2.Annotations["control.compliance.openshift.io/CIS-OCP"]).To(Equal("5.1.5"))

		profileRef2 := rule2.Annotations[cmpv1alpha1.RuleProfileAnnotationKey]
		Expect(profileRef2).To(ContainSubstring(GetPrefixedName(pbName, "cel-e2e-test-profile")))

		// --- Rule 3: check-namespaces-have-network-policies ---
		rule3 := &cmpv1alpha1.Rule{}
		Expect(client.Get(context.TODO(), types.NamespacedName{
			Name:      GetPrefixedName(pbName, "check-namespaces-have-network-policies"),
			Namespace: testNamespace,
		}, rule3)).To(Succeed())

		Expect(rule3.RulePayload.ScannerType).To(Equal(cmpv1alpha1.ScannerTypeCEL))
		Expect(rule3.RulePayload.ID).To(Equal("check_namespaces_have_network_policies"))
		Expect(rule3.RulePayload.Inputs).To(HaveLen(2))
		Expect(rule3.RulePayload.Inputs[0].Name).To(Equal("namespaces"))
		Expect(rule3.RulePayload.Inputs[1].Name).To(Equal("networkpolicies"))
		Expect(rule3.RulePayload.Inputs[1].KubernetesInputSpec.Group).To(Equal("networking.k8s.io"))
		Expect(rule3.Annotations["control.compliance.openshift.io/NIST-800-53"]).To(ContainSubstring("SC-7"))
		Expect(rule3.Annotations["control.compliance.openshift.io/CIS-OCP"]).To(Equal("5.3.2"))

		profileRef3 := rule3.Annotations[cmpv1alpha1.RuleProfileAnnotationKey]
		Expect(profileRef3).To(ContainSubstring(GetPrefixedName(pbName, "cel-e2e-test-profile")))

		// --- Rule 4: check-no-privileged-containers ---
		rule4 := &cmpv1alpha1.Rule{}
		Expect(client.Get(context.TODO(), types.NamespacedName{
			Name:      GetPrefixedName(pbName, "check-no-privileged-containers"),
			Namespace: testNamespace,
		}, rule4)).To(Succeed())

		Expect(rule4.RulePayload.ScannerType).To(Equal(cmpv1alpha1.ScannerTypeCEL))
		Expect(rule4.RulePayload.ID).To(Equal("check_no_privileged_containers"))
		Expect(rule4.RulePayload.Severity).To(Equal("high"))
		Expect(rule4.RulePayload.Inputs).To(HaveLen(1))
		Expect(rule4.RulePayload.Inputs[0].Name).To(Equal("pods"))
		Expect(rule4.RulePayload.FailureReason).To(ContainSubstring("privileged mode"))
		Expect(rule4.Annotations["control.compliance.openshift.io/NIST-800-53"]).To(ContainSubstring("AC-6(1)"))
		Expect(rule4.Annotations["control.compliance.openshift.io/NIST-800-53"]).To(ContainSubstring("AC-6(5)"))
		Expect(rule4.Annotations["control.compliance.openshift.io/CIS-OCP"]).To(Equal("5.2.1"))

		// --- Profile: cel-e2e-test-profile ---
		profile := &cmpv1alpha1.Profile{}
		Expect(client.Get(context.TODO(), types.NamespacedName{
			Name:      GetPrefixedName(pbName, "cel-e2e-test-profile"),
			Namespace: testNamespace,
		}, profile)).To(Succeed())

		Expect(profile.ID).To(Equal("cel_e2e_test_profile"))
		Expect(profile.Title).To(Equal("CEL E2E Test Profile"))
		Expect(profile.Description).To(ContainSubstring("end-to-end testing"))
		Expect(profile.Annotations[cmpv1alpha1.ScannerTypeAnnotation]).To(Equal(string(cmpv1alpha1.ScannerTypeCEL)))
		Expect(profile.Annotations[cmpv1alpha1.ProductTypeAnnotation]).To(Equal("Platform"))
		Expect(profile.Labels).To(HaveKey(cmpv1alpha1.ProfileGuidLabel))
		Expect(profile.Labels[cmpv1alpha1.ProfileBundleOwnerLabel]).To(Equal(pbName))

		Expect(profile.Rules).To(HaveLen(4))
		Expect(string(profile.Rules[0])).To(Equal(GetPrefixedName(pbName, "check-default-namespace-has-no-pods")))
		Expect(string(profile.Rules[1])).To(Equal(GetPrefixedName(pbName, "check-default-sa-exists-in-kube-system")))
		Expect(string(profile.Rules[2])).To(Equal(GetPrefixedName(pbName, "check-namespaces-have-network-policies")))
		Expect(string(profile.Rules[3])).To(Equal(GetPrefixedName(pbName, "check-no-privileged-containers")))
	})
})
