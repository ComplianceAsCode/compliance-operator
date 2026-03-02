package cel_e2e

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestMain(m *testing.M) {
	f := framework.NewFramework()
	err := f.SetUp()
	if err != nil {
		log.Fatal(err)
	}

	exitCode := m.Run()
	if exitCode == 0 || (exitCode > 0 && f.CleanUpOnError()) {
		if err = f.TearDown(); err != nil {
			log.Fatal(err)
		}
	}
	os.Exit(exitCode)
}

// TestCustomRuleTailoredProfile tests CustomRule functionality with TailoredProfiles
func TestCustomRuleTailoredProfile(t *testing.T) {
	t.Parallel()
	f := framework.Global

	testName := framework.GetObjNameFromTest(t)
	customRuleName := fmt.Sprintf("%s-security-context", testName)
	tpName := fmt.Sprintf("%s-tp", testName)
	ssbName := fmt.Sprintf("%s-ssb", testName)
	testNamespace := f.OperatorNamespace

	// Create a unique label for our test pods to ensure isolation
	// Only pods with this label will be checked by the CustomRule
	testLabel := fmt.Sprintf("test-customrule-%s", testName)
	// Create a pod without our test label to verify it's NOT checked by the rule
	ignoredPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-ignored-pod", testName),
			Namespace: testNamespace,
			// NO label - this pod should be ignored by our CustomRule
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:    "ignored-container",
					Image:   "busybox:latest",
					Command: []string{"sh", "-c", "sleep 3600"},
				},
			},
			// No security context, but should be ignored
		},
	}

	err := f.Client.Create(context.TODO(), ignoredPod, nil)
	if err != nil {
		t.Fatalf("Failed to create ignored pod: %v", err)
	}
	defer f.Client.Delete(context.TODO(), ignoredPod)

	// Create CustomRule that only checks our test pods
	customRule := &compv1alpha1.CustomRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      customRuleName,
			Namespace: testNamespace,
		},
		Spec: compv1alpha1.CustomRuleSpec{
			RulePayload: compv1alpha1.RulePayload{
				ID:          customRuleName,
				Title:       "Test Pods Must Have Security Context",
				Description: fmt.Sprintf("Ensures test pods with label customrule-test=%s have proper security context", testLabel),
				Severity:    "high",
			},
			CustomRulePayload: compv1alpha1.CustomRulePayload{
				ScannerType: compv1alpha1.ScannerTypeCEL,
				Expression: fmt.Sprintf(`
					pods.items.filter(pod,
						has(pod.metadata.labels) &&
						"customrule-test" in pod.metadata.labels &&
						pod.metadata.labels["customrule-test"] == "%s"
					).all(pod,
						has(pod.spec.securityContext) &&
						pod.spec.securityContext.runAsNonRoot == true
					)
				`, testLabel),
				Inputs: []compv1alpha1.InputPayload{
					{
						Name: "pods",
						KubernetesInputSpec: compv1alpha1.KubernetesInputSpec{
							APIVersion:        "v1",
							Resource:          "pods",
							ResourceNamespace: testNamespace,
						},
					},
				},
				FailureReason: fmt.Sprintf("Test pod(s) with label customrule-test=%s found without proper security context (runAsNonRoot must be true)", testLabel),
			},
		},
	}

	err = f.Client.Create(context.TODO(), customRule, nil)
	if err != nil {
		t.Fatalf("Failed to create CustomRule: %v", err)
	}
	defer f.Client.Delete(context.TODO(), customRule)

	// Wait for CustomRule to be validated and ready
	err = f.WaitForCustomRuleStatus(testNamespace, customRuleName, "Ready")
	if err != nil {
		t.Fatalf("CustomRule validation failed: %v", err)
	}

	// Create TailoredProfile with CustomRule
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: testNamespace,
			Annotations: map[string]string{
				compv1alpha1.DisableOutdatedReferenceValidation: "true",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "Custom Security Checks",
			Description: "Test profile using CEL-based CustomRules",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      customRuleName,
					Kind:      "CustomRule",
					Rationale: "Security best practice requires pods to run as non-root",
				},
			},
		},
	}

	err = f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatalf("Failed to create TailoredProfile: %v", err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	// Create ScanSettingBinding
	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ssbName,
			Namespace: testNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     tpName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}

	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatalf("Failed to create ScanSettingBinding: %v", err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// Wait for suite to be created and for scans to complete
	suiteName := ssbName

	// Wait for scans to complete
	// The scan should be NON-COMPLIANT because our test pod doesn't have the required security context
	err = f.WaitForSuiteScansStatus(testNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatalf("Scan did not complete as expected: %v", err)
	}
	// Create a test pod without security context (should fail the check)
	testPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-test-pod", testName),
			Namespace: testNamespace,
			Labels: map[string]string{
				"customrule-test": testLabel,
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:    "test-container",
					Image:   "busybox:latest",
					Command: []string{"sh", "-c", "sleep 3600"},
				},
			},
			// Deliberately not setting securityContext to test the CustomRule
		},
	}

	// Create test pod
	err = f.Client.Create(context.TODO(), testPod, nil)
	if err != nil {
		t.Fatalf("Failed to create test pod: %v", err)
	}
	defer f.Client.Delete(context.TODO(), testPod)

	suite := &compv1alpha1.ComplianceSuite{}
	key := types.NamespacedName{Name: suiteName, Namespace: testNamespace}
	if err := f.Client.Get(context.TODO(), key, suite); err != nil {
		t.Fatal(err)
	}
	// let's rescans and expect the check to be non compliant by deleting the suite
	err = f.Client.Delete(context.TODO(), suite)
	if err != nil {
		t.Fatalf("Failed to delete suite: %v", err)
	}
	err = f.WaitForSuiteScansStatus(testNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatalf("Scan did not complete as expected: %v", err)
	}

	// Validate that the CustomRule result is FAIL
	// For TailoredProfiles, the scan name is the TailoredProfile name
	scanName := tpName
	expectedCheck := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", scanName, customRuleName),
			Namespace: testNamespace,
		},
		ID:     customRuleName,
		Status: compv1alpha1.CheckResultFail,
	}

	err = f.AssertHasCheck(suiteName, scanName, expectedCheck)
	if err != nil {
		t.Fatalf("CustomRule validation failed: %v", err)
	}

	t.Logf("Created pod without label that should be ignored: %s", ignoredPod.Name)
	t.Log("Test completed successfully. CustomRule correctly:")
	t.Log("  - Identified non-compliant pod with the test label")
	t.Log("  - Ignored pods without the test label")
	t.Logf("  - Validated that rule %s has FAIL status", customRuleName)
}

func TestCustomRuleWithMultipleInputs(t *testing.T) {
	t.Parallel()
	f := framework.Global

	testName := framework.GetObjNameFromTest(t)
	customRuleName := fmt.Sprintf("%s-network-policy", testName)
	tpName := fmt.Sprintf("%s-tp", testName)
	ssbName := fmt.Sprintf("%s-ssb", testName)
	testNamespace := f.OperatorNamespace

	// Create test namespace without network policies
	testNs := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-test", testName),
		},
	}

	err := f.Client.Create(context.TODO(), testNs, nil)
	if err != nil {
		t.Fatalf("Failed to create test namespace: %v", err)
	}
	defer f.Client.Delete(context.TODO(), testNs)

	// Create CustomRule that checks for network policies in namespaces
	customRule := &compv1alpha1.CustomRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      customRuleName,
			Namespace: testNamespace,
		},
		Spec: compv1alpha1.CustomRuleSpec{
			RulePayload: compv1alpha1.RulePayload{
				ID:          customRuleName,
				Title:       "Namespaces Must Have Network Policies",
				Description: "Ensures all namespaces have at least one network policy",
				Severity:    "medium",
			},
			CustomRulePayload: compv1alpha1.CustomRulePayload{
				ScannerType: compv1alpha1.ScannerTypeCEL,
				Expression: `
					namespaces.items.all(ns,
						ns.metadata.name.startsWith("kube-") ||
						ns.metadata.name == "default" ||
						ns.metadata.name.startsWith("openshift") ||
						networkpolicies.items.exists(np,
							np.metadata.namespace == ns.metadata.name
						)
					)
				`,
				Inputs: []compv1alpha1.InputPayload{
					{
						Name: "namespaces",
						KubernetesInputSpec: compv1alpha1.KubernetesInputSpec{
							APIVersion: "v1",
							Resource:   "namespaces",
						},
					},
					{
						Name: "networkpolicies",
						KubernetesInputSpec: compv1alpha1.KubernetesInputSpec{
							Group:      "networking.k8s.io",
							APIVersion: "v1",
							Resource:   "networkpolicies",
						},
					},
				},
				FailureReason: "Namespace(s) found without network policies",
			},
		},
	}

	err = f.Client.Create(context.TODO(), customRule, nil)
	if err != nil {
		t.Fatalf("Failed to create CustomRule: %v", err)
	}
	defer f.Client.Delete(context.TODO(), customRule)

	// Wait for CustomRule to be validated and ready
	err = f.WaitForCustomRuleStatus(testNamespace, customRuleName, "Ready")
	if err != nil {
		t.Fatalf("CustomRule validation failed: %v", err)
	}

	// Create TailoredProfile with CustomRule
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: testNamespace,
			Annotations: map[string]string{
				compv1alpha1.DisableOutdatedReferenceValidation: "true",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "Network Policy Compliance",
			Description: "Test profile for network policy compliance",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      customRuleName,
					Kind:      "CustomRule",
					Rationale: "All namespaces should have network policies for security",
				},
			},
		},
	}

	err = f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatalf("Failed to create TailoredProfile: %v", err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	// Create ScanSettingBinding
	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ssbName,
			Namespace: testNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     tpName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}

	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatalf("Failed to create ScanSettingBinding: %v", err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// Wait for ScanSettingBinding to become ready
	err = f.WaitForScanSettingBindingStatus(testNamespace, ssbName, compv1alpha1.ScanSettingBindingPhaseReady)
	if err != nil {
		t.Fatalf("Failed waiting for ScanSettingBinding to become ready: %v", err)
	}
	t.Logf("ScanSettingBinding %s is now ready", ssbName)

	// Wait for suite to be created and for scans to complete
	suiteName := ssbName

	// Wait for scans to complete
	err = f.WaitForSuiteScansStatus(testNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatalf("Failed waiting for suite scans to complete: %v", err)
	}

	// Validate that the CustomRule result is FAIL
	// For TailoredProfiles, the scan name is the TailoredProfile name
	scanName := tpName
	expectedCheck := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", scanName, customRuleName),
			Namespace: testNamespace,
		},
		ID:     customRuleName,
		Status: compv1alpha1.CheckResultFail,
	}

	err = f.AssertHasCheck(suiteName, scanName, expectedCheck)
	if err != nil {
		t.Fatalf("CustomRule validation failed: %v", err)
	}

	t.Log("CustomRule with multiple inputs test completed successfully.")
	t.Logf("  - Validated that rule %s has FAIL status", customRuleName)
}

func TestCustomRuleValidation(t *testing.T) {
	t.Parallel()
	f := framework.Global

	testName := framework.GetObjNameFromTest(t)
	testNamespace := f.OperatorNamespace

	// Test 1: Invalid CEL expression
	invalidRule := &compv1alpha1.CustomRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-invalid", testName),
			Namespace: testNamespace,
		},
		Spec: compv1alpha1.CustomRuleSpec{
			RulePayload: compv1alpha1.RulePayload{
				ID:          fmt.Sprintf("%s-invalid", testName),
				Title:       "Invalid Rule",
				Description: "This rule has invalid CEL expression",
				Severity:    "low",
			},
			CustomRulePayload: compv1alpha1.CustomRulePayload{
				ScannerType: compv1alpha1.ScannerTypeCEL,
				Expression: `
					pods.items.all(pod,
						invalid_function_that_doesnt_exist(pod)
					)
				`,
				Inputs: []compv1alpha1.InputPayload{
					{
						Name: "pods",
						KubernetesInputSpec: compv1alpha1.KubernetesInputSpec{
							APIVersion: "v1",
							Resource:   "pods",
						},
					},
				},
				FailureReason: "This should fail validation",
			},
		},
	}

	err := f.Client.Create(context.TODO(), invalidRule, nil)
	if err != nil {
		t.Fatalf("Failed to create CustomRule: %v", err)
	}
	defer f.Client.Delete(context.TODO(), invalidRule)

	// Wait and expect the rule to have Error status
	err = f.WaitForCustomRuleStatus(testNamespace, fmt.Sprintf("%s-invalid", testName), "Error")
	if err != nil {
		t.Fatalf("CustomRule validation failed: %v", err)
	}
	t.Log("CustomRule validation correctly rejected invalid expression")

	// Test 2: Rule with undeclared variable
	undeclaredVarRule := &compv1alpha1.CustomRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-undeclared", testName),
			Namespace: testNamespace,
		},
		Spec: compv1alpha1.CustomRuleSpec{
			RulePayload: compv1alpha1.RulePayload{
				ID:          fmt.Sprintf("%s-undeclared", testName),
				Title:       "Undeclared Variable Rule",
				Description: "This rule uses undeclared variables",
				Severity:    "low",
			},
			CustomRulePayload: compv1alpha1.CustomRulePayload{
				ScannerType: compv1alpha1.ScannerTypeCEL,
				Expression: `
					pods.items.all(pod,
						deployments.items.exists(d, d.metadata.name == pod.metadata.name)
					)
				`,
				Inputs: []compv1alpha1.InputPayload{
					{
						Name: "pods",
						KubernetesInputSpec: compv1alpha1.KubernetesInputSpec{
							APIVersion: "v1",
							Resource:   "pods",
						},
					},
					// 'deployments' is used but not declared as input
				},
				FailureReason: "This should fail validation due to undeclared variable",
			},
		},
	}

	err = f.Client.Create(context.TODO(), undeclaredVarRule, nil)
	if err != nil {
		t.Fatalf("Failed to create CustomRule: %v", err)
	}
	defer f.Client.Delete(context.TODO(), undeclaredVarRule)

	// Wait and expect the rule to have Error status
	err = f.WaitForCustomRuleStatus(testNamespace, fmt.Sprintf("%s-undeclared", testName), "Error")
	if err != nil {
		t.Fatalf("CustomRule validation failed: %v", err)
	}
	t.Log("CustomRule validation correctly detected undeclared variable")

}

func TestCustomRuleCheckTypeAndScannerTypeValidation(t *testing.T) {
	t.Parallel()
	f := framework.Global

	testName := framework.GetObjNameFromTest(t)
	testNamespace := f.OperatorNamespace

	// Test 1: Invalid checkType (should be Platform only)
	invalidCheckTypeRule := &compv1alpha1.CustomRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-invalid-checktype", testName),
			Namespace: testNamespace,
		},
		Spec: compv1alpha1.CustomRuleSpec{
			RulePayload: compv1alpha1.RulePayload{
				ID:          fmt.Sprintf("%s-invalid-checktype", testName),
				Title:       "Invalid CheckType Rule",
				Description: "This rule has invalid checkType",
				Severity:    "low",
				CheckType:   "Node", // This should be rejected
			},
			CustomRulePayload: compv1alpha1.CustomRulePayload{
				ScannerType: compv1alpha1.ScannerTypeCEL,
				Expression:  `pods.items.size() >= 0`,
				Inputs: []compv1alpha1.InputPayload{
					{
						Name: "pods",
						KubernetesInputSpec: compv1alpha1.KubernetesInputSpec{
							APIVersion: "v1",
							Resource:   "pods",
						},
					},
				},
				FailureReason: "This should fail validation due to invalid checkType",
			},
		},
	}

	err := f.Client.Create(context.TODO(), invalidCheckTypeRule, nil)
	if err != nil {
		t.Fatalf("Failed to create CustomRule: %v", err)
	}
	defer f.Client.Delete(context.TODO(), invalidCheckTypeRule)

	// Wait and expect the rule to have Error status
	err = f.WaitForCustomRuleStatus(testNamespace, fmt.Sprintf("%s-invalid-checktype", testName), "Error")
	if err != nil {
		t.Fatalf("CustomRule validation should have failed for invalid checkType: %v", err)
	}
	t.Log("CustomRule validation correctly rejected invalid checkType")

	// Test 2: Invalid scannerType (should be CEL only)
	invalidScannerTypeRule := &compv1alpha1.CustomRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-invalid-scannertype", testName),
			Namespace: testNamespace,
		},
		Spec: compv1alpha1.CustomRuleSpec{
			RulePayload: compv1alpha1.RulePayload{
				ID:          fmt.Sprintf("%s-invalid-scannertype", testName),
				Title:       "Invalid ScannerType Rule",
				Description: "This rule has invalid scannerType",
				Severity:    "low",
				CheckType:   "Platform", // Valid checkType
			},
			CustomRulePayload: compv1alpha1.CustomRulePayload{
				ScannerType: compv1alpha1.ScannerTypeOpenSCAP, // This should be rejected
				Expression:  `pods.items.size() >= 0`,
				Inputs: []compv1alpha1.InputPayload{
					{
						Name: "pods",
						KubernetesInputSpec: compv1alpha1.KubernetesInputSpec{
							APIVersion: "v1",
							Resource:   "pods",
						},
					},
				},
				FailureReason: "This should fail validation due to invalid scannerType",
			},
		},
	}

	err = f.Client.Create(context.TODO(), invalidScannerTypeRule, nil)
	if err == nil {
		t.Fatalf("we should not be able to create a CustomRule with an invalid scannerType")
	}

	t.Log("CustomRule validation correctly rejected invalid scannerType")

	// Test 3: Valid CustomRule with Platform checkType and CEL scannerType
	validRule := &compv1alpha1.CustomRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-valid", testName),
			Namespace: testNamespace,
		},
		Spec: compv1alpha1.CustomRuleSpec{
			RulePayload: compv1alpha1.RulePayload{
				ID:          fmt.Sprintf("%s-valid", testName),
				Title:       "Valid Rule",
				Description: "This rule has valid checkType and scannerType",
				Severity:    "low",
				CheckType:   "Platform", // Valid checkType
			},
			CustomRulePayload: compv1alpha1.CustomRulePayload{
				ScannerType: compv1alpha1.ScannerTypeCEL, // Valid scannerType
				Expression:  `pods.items.size() >= 0`,
				Inputs: []compv1alpha1.InputPayload{
					{
						Name: "pods",
						KubernetesInputSpec: compv1alpha1.KubernetesInputSpec{
							APIVersion: "v1",
							Resource:   "pods",
						},
					},
				},
				FailureReason: "This should pass validation",
			},
		},
	}

	err = f.Client.Create(context.TODO(), validRule, nil)
	if err != nil {
		t.Fatalf("Failed to create CustomRule: %v", err)
	}
	defer f.Client.Delete(context.TODO(), validRule)

	// Wait and expect the rule to have Ready status
	err = f.WaitForCustomRuleStatus(testNamespace, fmt.Sprintf("%s-valid", testName), "Ready")
	if err != nil {
		t.Fatalf("CustomRule validation should have passed for valid rule: %v", err)
	}
	t.Log("CustomRule validation correctly accepted valid checkType and scannerType")

	// Test 4: Valid CustomRule with empty checkType (should default to Platform)
	validEmptyCheckTypeRule := &compv1alpha1.CustomRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-valid-empty-checktype", testName),
			Namespace: testNamespace,
		},
		Spec: compv1alpha1.CustomRuleSpec{
			RulePayload: compv1alpha1.RulePayload{
				ID:          fmt.Sprintf("%s-valid-empty-checktype", testName),
				Title:       "Valid Empty CheckType Rule",
				Description: "This rule has empty checkType which should be valid",
				Severity:    "low",
				// CheckType is empty, which should be valid
			},
			CustomRulePayload: compv1alpha1.CustomRulePayload{
				ScannerType: compv1alpha1.ScannerTypeCEL, // Valid scannerType
				Expression:  `pods.items.size() >= 0`,
				Inputs: []compv1alpha1.InputPayload{
					{
						Name: "pods",
						KubernetesInputSpec: compv1alpha1.KubernetesInputSpec{
							APIVersion: "v1",
							Resource:   "pods",
						},
					},
				},
				FailureReason: "This should pass validation with empty checkType",
			},
		},
	}

	err = f.Client.Create(context.TODO(), validEmptyCheckTypeRule, nil)
	if err != nil {
		t.Fatalf("Failed to create CustomRule: %v", err)
	}
	defer f.Client.Delete(context.TODO(), validEmptyCheckTypeRule)

	// Wait and expect the rule to have Ready status
	err = f.WaitForCustomRuleStatus(testNamespace, fmt.Sprintf("%s-valid-empty-checktype", testName), "Ready")
	if err != nil {
		t.Fatalf("CustomRule validation should have passed for rule with empty checkType: %v", err)
	}
	t.Log("CustomRule validation correctly accepted empty checkType")
}

func TestTailoredProfileRejectsMixedRuleTypes(t *testing.T) {
	t.Parallel()
	f := framework.Global

	testName := framework.GetObjNameFromTest(t)
	testNamespace := f.OperatorNamespace
	customRuleName := fmt.Sprintf("%s-custom", testName)
	tpName := fmt.Sprintf("%s-tp-mixed", testName)
	expression := `pods.items.all(pod, pod.spec.containers.all(container, !has(container.securityContext) || !has(container.securityContext.privileged) || container.securityContext.privileged == false ))`
	// Step 1: Create a valid CustomRule
	customRule := &compv1alpha1.CustomRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      customRuleName,
			Namespace: testNamespace,
		},
		Spec: compv1alpha1.CustomRuleSpec{
			RulePayload: compv1alpha1.RulePayload{
				ID:          customRuleName,
				Title:       "No Privileged Containers",
				Description: "Ensures no containers are running in privileged mode",
				Severity:    "high",
			},
			CustomRulePayload: compv1alpha1.CustomRulePayload{
				ScannerType: compv1alpha1.ScannerTypeCEL,
				Expression:  expression,
				Inputs: []compv1alpha1.InputPayload{
					{
						Name: "pods",
						KubernetesInputSpec: compv1alpha1.KubernetesInputSpec{
							APIVersion: "v1",
							Resource:   "pods",
						},
					},
				},
				FailureReason: "Privileged container(s) found",
			},
		},
	}

	err := f.Client.Create(context.TODO(), customRule, nil)
	if err != nil {
		t.Fatalf("Failed to create CustomRule: %v", err)
	}
	defer f.Client.Delete(context.TODO(), customRule)

	// Wait for CustomRule to be validated and ready
	err = f.WaitForCustomRuleStatus(testNamespace, customRuleName, "Ready")
	if err != nil {
		t.Fatalf("CustomRule validation failed: %v", err)
	}
	t.Logf("CustomRule %s is ready", customRuleName)

	// Step 2: Create TailoredProfile that mixes CustomRules and regular Rules
	// This should fail validation
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: testNamespace,
			Annotations: map[string]string{
				compv1alpha1.DisableOutdatedReferenceValidation: "true",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "Mixed Rule Types Test",
			Description: "This profile incorrectly mixes CustomRules and regular Rules",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					// CustomRule - CEL-based
					Name:      customRuleName,
					Kind:      "CustomRule",
					Rationale: "Ensure containers are not privileged",
				},
				{
					// Regular Rule - OpenSCAP-based
					Name:      "ocp4-cluster-version-operator-exists",
					Kind:      "Rule",
					Rationale: "Make sure cluster version operator exists",
				},
			},
		},
	}

	err = f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatalf("Failed to create TailoredProfile: %v", err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	// Step 3: Wait for TailoredProfile to be in Error state
	err = f.WaitForTailoredProfileStatus(testNamespace, tpName, compv1alpha1.TailoredProfileStateError)
	if err != nil {
		t.Fatalf("TailoredProfile did not enter Error state: %v", err)
	}
	t.Logf("TailoredProfile %s is in Error state as expected", tpName)

	// Step 4: Verify the error message
	tpWithError := &compv1alpha1.TailoredProfile{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: tpName, Namespace: testNamespace}, tpWithError)
	if err != nil {
		t.Fatalf("Failed to get TailoredProfile: %v", err)
	}

	expectedErrorContent := "cannot mix CustomRules and regular Rules"
	if !strings.Contains(tpWithError.Status.ErrorMessage, expectedErrorContent) {
		t.Fatalf("Expected error message to contain '%s', but got: %s", expectedErrorContent, tpWithError.Status.ErrorMessage)
	}
	t.Logf("Error message correctly indicates mixed rule types: %s", tpWithError.Status.ErrorMessage)

	// Step 5: Create a TailoredProfile with only CustomRules (should work)
	tpValidName := fmt.Sprintf("%s-tp-valid", testName)
	tpValid := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpValidName,
			Namespace: testNamespace,
			Annotations: map[string]string{
				compv1alpha1.DisableOutdatedReferenceValidation: "true",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "CustomRules Only Test",
			Description: "This profile correctly uses only CustomRules",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      customRuleName,
					Kind:      "CustomRule",
					Rationale: "Ensure containers are not privileged",
				},
			},
		},
	}

	err = f.Client.Create(context.TODO(), tpValid, nil)
	if err != nil {
		t.Fatalf("Failed to create valid TailoredProfile: %v", err)
	}
	defer f.Client.Delete(context.TODO(), tpValid)

	// Should be ready since it only has CustomRules
	err = f.WaitForTailoredProfileStatus(testNamespace, tpValidName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatalf("Valid TailoredProfile did not become ready: %v", err)
	}
	t.Logf("TailoredProfile %s with only CustomRules is ready as expected", tpValidName)

	// Step 6: Create a TailoredProfile with only regular Rules (should work)
	tpRegularName := fmt.Sprintf("%s-tp-regular", testName)
	tpRegular := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpRegularName,
			Namespace: testNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "Regular Rules Only Test",
			Description: "This profile correctly uses only regular Rules",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-cluster-version-operator-exists",
					Rationale: "Make sure cluster version operator exists",
				},
				{
					Name:      "ocp4-kubeadmin-removed",
					Kind:      "Rule", // Explicitly set Kind to Rule
					Rationale: "Ensure kubeadmin user has been removed",
				},
			},
		},
	}

	err = f.Client.Create(context.TODO(), tpRegular, nil)
	if err != nil {
		t.Fatalf("Failed to create regular TailoredProfile: %v", err)
	}
	defer f.Client.Delete(context.TODO(), tpRegular)

	// Should be ready since it only has regular Rules
	err = f.WaitForTailoredProfileStatus(testNamespace, tpRegularName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatalf("Regular TailoredProfile did not become ready: %v", err)
	}
	t.Logf("TailoredProfile %s with only regular Rules is ready as expected", tpRegularName)

	// Step 7: Test updating from valid to invalid (adding a different rule type)
	// Get the valid CustomRule-only profile
	tpToUpdate := &compv1alpha1.TailoredProfile{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: tpValidName, Namespace: testNamespace}, tpToUpdate)
	if err != nil {
		t.Fatalf("Failed to get TailoredProfile for update: %v", err)
	}

	// Update to add a regular Rule, making it invalid
	tpToUpdateCopy := tpToUpdate.DeepCopy()
	tpToUpdateCopy.Spec.EnableRules = append(tpToUpdateCopy.Spec.EnableRules, compv1alpha1.RuleReferenceSpec{
		Name:      "ocp4-cluster-version-operator-exists",
		Kind:      "Rule",
		Rationale: "Adding regular rule to make it invalid",
	})

	err = f.Client.Update(context.TODO(), tpToUpdateCopy)
	if err != nil {
		t.Fatalf("Failed to update TailoredProfile: %v", err)
	}

	// Should go to Error state
	err = f.WaitForTailoredProfileStatus(testNamespace, tpValidName, compv1alpha1.TailoredProfileStateError)
	if err != nil {
		t.Fatalf("Updated TailoredProfile did not enter Error state: %v", err)
	}
	t.Logf("TailoredProfile %s correctly went to Error state after adding mixed rule types", tpValidName)

	t.Log("TestTailoredProfileRejectsMixedRuleTypes completed successfully")
}

func TestCustomRuleFailureReasonInCheckResult(t *testing.T) {
	t.Parallel()
	f := framework.Global

	testName := framework.GetObjNameFromTest(t)
	testNamespace := f.OperatorNamespace
	customRuleName := fmt.Sprintf("%s-replica-check", testName)
	tpName := fmt.Sprintf("%s-tp", testName)
	ssbName := fmt.Sprintf("%s-ssb", testName)

	// Create a CustomRule that will intentionally fail with a specific failure reason
	customRule := &compv1alpha1.CustomRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      customRuleName,
			Namespace: testNamespace,
		},
		Spec: compv1alpha1.CustomRuleSpec{
			RulePayload: compv1alpha1.RulePayload{
				ID:          fmt.Sprintf("custom_%s", customRuleName),
				Title:       "Ensure Deployments Have at Least 3 Replicas",
				Description: "Validates that all deployments have at least 3 replicas for high availability",
				Severity:    "medium",
			},
			CustomRulePayload: compv1alpha1.CustomRulePayload{
				ScannerType: compv1alpha1.ScannerTypeCEL,
				Expression: `
					deployments.items.all(deployment,
						deployment.spec.replicas >= 3
					)
				`,
				Inputs: []compv1alpha1.InputPayload{
					{
						Name: "deployments",
						KubernetesInputSpec: compv1alpha1.KubernetesInputSpec{
							Group:             "apps",
							APIVersion:        "v1",
							Resource:          "deployments",
							ResourceNamespace: testNamespace,
						},
					},
				},
				FailureReason: "One or more deployments have less than 3 replicas, which violates the high availability requirement",
			},
		},
	}

	err := f.Client.Create(context.TODO(), customRule, nil)
	if err != nil {
		t.Fatalf("Failed to create CustomRule: %v", err)
	}
	defer f.Client.Delete(context.TODO(), customRule)

	// Wait for CustomRule to be validated and ready
	err = f.WaitForCustomRuleStatus(testNamespace, customRuleName, "Ready")
	if err != nil {
		t.Fatalf("CustomRule validation failed: %v", err)
	}
	t.Logf("CustomRule %s is ready", customRuleName)

	// Create TailoredProfile with the CustomRule
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: testNamespace,
			Annotations: map[string]string{
				compv1alpha1.DisableOutdatedReferenceValidation: "true",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "Test Failure Reason",
			Description: "Test that FailureReason appears in ComplianceCheckResult",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      customRuleName,
					Kind:      "CustomRule",
					Rationale: "Testing failure reason propagation",
				},
			},
		},
	}

	err = f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatalf("Failed to create TailoredProfile: %v", err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	// Wait for TailoredProfile to be ready
	err = f.WaitForTailoredProfileStatus(testNamespace, tpName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatalf("TailoredProfile failed to become ready: %v", err)
	}
	t.Logf("TailoredProfile %s is ready", tpName)

	// Create ScanSettingBinding
	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ssbName,
			Namespace: testNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     tpName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}

	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatalf("Failed to create ScanSettingBinding: %v", err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// Wait for scans to complete
	// The scan should be NON-COMPLIANT because the compliance-operator deployment likely has only 1 replica
	suiteName := ssbName
	err = f.WaitForSuiteScansStatus(testNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		// It might be compliant if there are 3+ replicas, which is okay for this test
		// We just need to check that the scan completed
		err = f.WaitForSuiteScansStatus(testNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
		if err != nil {
			t.Fatalf("Scan did not complete: %v", err)
		}
		t.Log("Scan completed as compliant (deployments have 3+ replicas)")
	} else {
		t.Log("Scan completed as non-compliant (some deployments have <3 replicas)")

		// Get the ComplianceCheckResult and verify the FailureReason appears in warnings
		checkResultName := fmt.Sprintf("%s-%s", tpName, strings.ReplaceAll(fmt.Sprintf("custom_%s", customRuleName), "_", "-"))
		checkResult := &compv1alpha1.ComplianceCheckResult{}
		err = f.Client.Get(context.TODO(), types.NamespacedName{
			Name:      checkResultName,
			Namespace: testNamespace,
		}, checkResult)
		if err != nil {
			t.Fatalf("Failed to get ComplianceCheckResult: %v", err)
		}

		// Verify the check failed
		if checkResult.Status != compv1alpha1.CheckResultFail {
			t.Logf("Check result status is %s, not FAIL - deployments might have 3+ replicas", checkResult.Status)
		} else {
			// Verify the FailureReason appears in the warnings
			expectedFailureReason := "One or more deployments have less than 3 replicas, which violates the high availability requirement"
			found := false
			for _, warning := range checkResult.Warnings {
				if warning == expectedFailureReason {
					found = true
					break
				}
			}

			if !found {
				t.Fatalf("Expected FailureReason not found in warnings. Warnings: %v", checkResult.Warnings)
			}
			t.Logf("FailureReason correctly appears in ComplianceCheckResult warnings: %s", expectedFailureReason)
		}
	}

	// Create a deployment with only 1 replica to ensure the rule fails
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-test-deployment", testName),
			Namespace: testNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: func() *int32 { i := int32(1); return &i }(),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": fmt.Sprintf("%s-test", testName),
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": fmt.Sprintf("%s-test", testName),
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:    "test-container",
							Image:   "busybox:latest",
							Command: []string{"sh", "-c", "sleep 3600"},
						},
					},
				},
			},
		},
	}

	err = f.Client.Create(context.TODO(), deployment, nil)
	if err != nil {
		t.Fatalf("Failed to create test deployment: %v", err)
	}
	defer f.Client.Delete(context.TODO(), deployment)

	// Re-run the scan to ensure it fails
	suite := &compv1alpha1.ComplianceSuite{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: suiteName, Namespace: testNamespace}, suite)
	if err != nil {
		t.Fatalf("Failed to get ComplianceSuite: %v", err)
	}

	// Delete and recreate the suite to trigger a new scan
	err = f.Client.Delete(context.TODO(), suite)
	if err != nil {
		t.Fatalf("Failed to delete ComplianceSuite: %v", err)
	}

	// Wait for the new scan to complete
	err = f.WaitForSuiteScansStatus(testNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatalf("Re-run scan did not complete as non-compliant: %v", err)
	}

	// Get the ComplianceCheckResult again and verify the FailureReason
	checkResultName := fmt.Sprintf("%s-%s", tpName, strings.ReplaceAll(fmt.Sprintf("custom_%s", customRuleName), "_", "-"))
	checkResult := &compv1alpha1.ComplianceCheckResult{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{
		Name:      checkResultName,
		Namespace: testNamespace,
	}, checkResult)
	if err != nil {
		t.Fatalf("Failed to get ComplianceCheckResult after re-run: %v", err)
	}

	// Verify the check failed
	if checkResult.Status != compv1alpha1.CheckResultFail {
		t.Fatalf("Expected check result status to be FAIL but got %s", checkResult.Status)
	}

	// Verify the FailureReason appears in the warnings
	expectedFailureReason := "One or more deployments have less than 3 replicas, which violates the high availability requirement"
	found := false
	for _, warning := range checkResult.Warnings {
		if warning == expectedFailureReason {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("Expected FailureReason not found in warnings after re-run. Warnings: %v", checkResult.Warnings)
	}

	t.Logf("FailureReason correctly appears in ComplianceCheckResult warnings: %s", expectedFailureReason)
	t.Log("TestCustomRuleFailureReasonInCheckResult completed successfully")
}

func TestCustomRuleCascadingStatusUpdate(t *testing.T) {
	t.Parallel()
	f := framework.Global

	testName := framework.GetObjNameFromTest(t)
	testNamespace := f.OperatorNamespace
	customRuleName := fmt.Sprintf("%s-cel", testName)
	tpName := fmt.Sprintf("%s-tp", testName)
	ssbName := fmt.Sprintf("%s-ssb", testName)

	// Step 1: Create a valid CustomRule
	validRule := &compv1alpha1.CustomRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      customRuleName,
			Namespace: testNamespace,
		},
		Spec: compv1alpha1.CustomRuleSpec{
			RulePayload: compv1alpha1.RulePayload{
				ID:          customRuleName,
				Title:       "Pods Must Have Security Context",
				Description: "Ensures all pods have security context defined with runAsNonRoot set to true",
				Severity:    "medium",
			},
			CustomRulePayload: compv1alpha1.CustomRulePayload{
				ScannerType: compv1alpha1.ScannerTypeCEL,
				Expression: `pods.items.all(pod, pod.spec.securityContext != null && pod.spec.securityContext.runAsNonRoot == true)
				`,
				Inputs: []compv1alpha1.InputPayload{
					{
						Name: "pods",
						KubernetesInputSpec: compv1alpha1.KubernetesInputSpec{
							APIVersion: "v1",
							Resource:   "pods",
						},
					},
				},
				FailureReason: "Pod(s) found without resource limits",
			},
		},
	}

	err := f.Client.Create(context.TODO(), validRule, nil)
	if err != nil {
		t.Fatalf("Failed to create CustomRule: %v", err)
	}
	defer f.Client.Delete(context.TODO(), validRule)

	// Wait for CustomRule to be validated and ready
	err = f.WaitForCustomRuleStatus(testNamespace, customRuleName, "Ready")
	if err != nil {
		t.Fatalf("CustomRule validation failed: %v", err)
	}
	t.Logf("CustomRule %s is ready", customRuleName)

	// Step 2: Create TailoredProfile with CustomRule
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: testNamespace,
			Annotations: map[string]string{
				compv1alpha1.DisableOutdatedReferenceValidation: "true",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "Cascading Test Profile",
			Description: "Test profile for cascading status updates",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      customRuleName,
					Kind:      "CustomRule",
					Rationale: "Pods should have resource limits for stability",
				},
			},
		},
	}

	err = f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatalf("Failed to create TailoredProfile: %v", err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	// Wait for TailoredProfile to be ready
	err = f.WaitForTailoredProfileStatus(testNamespace, tpName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatalf("TailoredProfile failed to become ready: %v", err)
	}
	t.Logf("TailoredProfile %s is ready", tpName)

	// Step 3: Create ScanSettingBinding
	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ssbName,
			Namespace: testNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     tpName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}

	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatalf("Failed to create ScanSettingBinding: %v", err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// Wait for ScanSettingBinding to become ready
	err = f.WaitForScanSettingBindingStatus(testNamespace, ssbName, compv1alpha1.ScanSettingBindingPhaseReady)
	if err != nil {
		t.Fatalf("Failed waiting for ScanSettingBinding to become ready: %v", err)
	}
	t.Logf("ScanSettingBinding %s is ready", ssbName)

	// Step 4: Update CustomRule with invalid expression
	t.Log("Updating CustomRule with invalid expression")

	// Fetch the current rule
	currentRule := &compv1alpha1.CustomRule{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: customRuleName, Namespace: testNamespace}, currentRule)
	if err != nil {
		t.Fatalf("Failed to get CustomRule: %v", err)
	}

	// Update with invalid expression
	currentRule.Spec.CustomRulePayload.Expression = `podsx.items.all(pod, pod.spec.securityContext != null && pod.spec.securityContext.runAsNonRoot == true)`

	err = f.Client.Update(context.TODO(), currentRule)
	if err != nil {
		t.Fatalf("Failed to update CustomRule: %v", err)
	}

	// Step 5: Wait for cascading error states
	t.Log("Waiting for cascading error states...")

	// CustomRule should go to Error state
	err = f.WaitForCustomRuleStatus(testNamespace, customRuleName, "Error")
	if err != nil {
		t.Fatalf("CustomRule did not enter Error state: %v", err)
	}
	t.Logf("CustomRule %s is now in Error state", customRuleName)

	// TailoredProfile should go to Error state
	err = f.WaitForTailoredProfileStatus(testNamespace, tpName, compv1alpha1.TailoredProfileStateError)
	if err != nil {
		t.Fatalf("TailoredProfile did not enter Error state: %v", err)
	}
	t.Logf("TailoredProfile %s is now in Error state", tpName)

	// ScanSettingBinding should go to Invalid state
	err = f.WaitForScanSettingBindingStatus(testNamespace, ssbName, compv1alpha1.ScanSettingBindingPhaseInvalid)
	if err != nil {
		t.Fatalf("ScanSettingBinding did not enter Invalid state: %v", err)
	}
	t.Logf("ScanSettingBinding %s is now in Invalid state", ssbName)

	// Step 6: Fix the CustomRule expression
	t.Log("Fixing CustomRule expression")

	// Fetch the current rule again
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: customRuleName, Namespace: testNamespace}, currentRule)
	if err != nil {
		t.Fatalf("Failed to get CustomRule: %v", err)
	}

	// Update with a valid but different expression to ensure change is detected
	currentRule.Spec.CustomRulePayload.Expression = `pods.items.all(pod, pod.spec.securityContext != null && pod.spec.securityContext.runAsNonRoot == true)`

	err = f.Client.Update(context.TODO(), currentRule)
	if err != nil {
		t.Fatalf("Failed to update CustomRule with fix: %v", err)
	}

	// Step 7: Wait for everything to recover
	t.Log("Waiting for resources to recover to good state...")

	// CustomRule should go back to Ready state
	err = f.WaitForCustomRuleStatus(testNamespace, customRuleName, "Ready")
	if err != nil {
		t.Fatalf("CustomRule did not recover to Ready state: %v", err)
	}
	t.Logf("CustomRule %s recovered to Ready state", customRuleName)

	// TailoredProfile should go back to Ready state
	err = f.WaitForTailoredProfileStatus(testNamespace, tpName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatalf("TailoredProfile did not recover to Ready state: %v", err)
	}
	t.Logf("TailoredProfile %s recovered to Ready state", tpName)

	// ScanSettingBinding should go back to Ready state
	err = f.WaitForScanSettingBindingStatus(testNamespace, ssbName, compv1alpha1.ScanSettingBindingPhaseReady)
	if err != nil {
		t.Fatalf("ScanSettingBinding did not recover to Ready state: %v", err)
	}
	t.Logf("ScanSettingBinding %s recovered to Ready state", ssbName)

	t.Log("CustomRule cascading status update test completed successfully")
}
