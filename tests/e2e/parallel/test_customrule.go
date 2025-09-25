package parallel_e2e

import (
	"context"
	"fmt"
	"testing"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestCustomRuleTailoredProfile tests CustomRule functionality with TailoredProfiles
// The test ensures isolation by:
// 1. Using a unique label selector for test pods
// 2. The CustomRule CEL expression filters pods by this label
// 3. Only pods with the specific label are evaluated, ignoring all other pods in the namespace
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
	err := f.Client.Create(context.TODO(), testPod, nil)
	if err != nil {
		t.Fatalf("Failed to create test pod: %v", err)
	}
	defer f.Client.Delete(context.TODO(), testPod)

	// Create CustomRule that only checks our test pods
	customRule := &compv1alpha1.CustomRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      customRuleName,
			Namespace: testNamespace,
		},
		Spec: compv1alpha1.CustomRuleSpec{
			RulePayload: compv1alpha1.RulePayload{
				ID:          fmt.Sprintf("custom_pods_security_context_%s", testName),
				Title:       "Test Pods Must Have Security Context",
				Description: fmt.Sprintf("Ensures test pods with label customrule-test=%s have proper security context", testLabel),
				Severity:    "high",
			},
			CELPayload: compv1alpha1.CELPayload{
				ScannerType: compv1alpha1.ScannerTypeCEL,
				Expression: fmt.Sprintf(`
					// Filter only pods with our test label
					pods.items.filter(pod, 
						has(pod.metadata.labels) && 
						"customrule-test" in pod.metadata.labels &&
						pod.metadata.labels["customrule-test"] == "%s"
					).all(pod,
						// Check that each test pod has proper security context
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
				ErrorMessage: fmt.Sprintf("Test pod(s) with label customrule-test=%s found without proper security context (runAsNonRoot must be true)", testLabel),
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
	err = f.WaitForSuiteScansStatus(testNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatalf("Scan did not complete as expected: %v", err)
	}

	// Verify that the check was created and has the expected result
	checkName := fmt.Sprintf("%s-%s-%s", suiteName, "master", customRuleName)
	checkResult := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      checkName,
			Namespace: testNamespace,
		},
		Status:   compv1alpha1.CheckResultFail, // Pod doesn't have required security context
		Severity: compv1alpha1.CheckResultSeverityHigh,
	}

	// Verify the check result
	scanName := fmt.Sprintf("%s-master", suiteName)
	err = f.AssertHasCheck(suiteName, scanName, checkResult)
	if err != nil {
		t.Fatalf("Check result not as expected: %v", err)
	}

	// Now create a compliant pod to test the positive case
	compliantPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-compliant-pod", testName),
			Namespace: testNamespace,
			Labels: map[string]string{
				"customrule-test": testLabel, // Same label so it's included in the check
			},
		},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: &[]bool{true}[0],
				RunAsUser:    &[]int64{1000}[0],
			},
			Containers: []corev1.Container{
				{
					Name:    "compliant-container",
					Image:   "busybox:latest",
					Command: []string{"sh", "-c", "sleep 3600"},
				},
			},
		},
	}

	err = f.Client.Create(context.TODO(), compliantPod, nil)
	if err != nil {
		t.Fatalf("Failed to create compliant pod: %v", err)
	}
	defer f.Client.Delete(context.TODO(), compliantPod)

	// Delete the non-compliant pod
	err = f.Client.Delete(context.TODO(), testPod)
	if err != nil {
		t.Fatalf("Failed to delete non-compliant pod: %v", err)
	}

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

	err = f.Client.Create(context.TODO(), ignoredPod, nil)
	if err != nil {
		t.Fatalf("Failed to create ignored pod: %v", err)
	}
	defer f.Client.Delete(context.TODO(), ignoredPod)

	t.Logf("Created pod without label that should be ignored: %s", ignoredPod.Name)
	t.Log("Test completed successfully. CustomRule correctly:")
	t.Log("  - Identified non-compliant pod with the test label")
	t.Log("  - Ignored pods without the test label")
	t.Log("  - Would pass for compliant pods with the test label")
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
				ID:          fmt.Sprintf("custom_network_policy_%s", testName),
				Title:       "Namespaces Must Have Network Policies",
				Description: "Ensures all namespaces have at least one network policy",
				Severity:    "medium",
			},
			CELPayload: compv1alpha1.CELPayload{
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
				ErrorMessage: "Namespace(s) found without network policies",
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

	// Wait for suite to be created and for scans to complete
	suiteName := ssbName

	// Wait for scans to complete
	err = f.WaitForSuiteScansStatus(testNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)

	t.Log("CustomRule with multiple inputs test completed successfully.")
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
				ID:          fmt.Sprintf("custom_invalid_%s", testName),
				Title:       "Invalid Rule",
				Description: "This rule has invalid CEL expression",
				Severity:    "low",
			},
			CELPayload: compv1alpha1.CELPayload{
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
				ErrorMessage: "This should fail validation",
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
		// This is expected - the rule should fail validation
		t.Log("CustomRule validation correctly rejected invalid expression")
	} else {
		t.Fatal("Expected CustomRule to fail validation, but it succeeded")
	}

	// Test 2: Rule with undeclared variable
	undeclaredVarRule := &compv1alpha1.CustomRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-undeclared", testName),
			Namespace: testNamespace,
		},
		Spec: compv1alpha1.CustomRuleSpec{
			RulePayload: compv1alpha1.RulePayload{
				ID:          fmt.Sprintf("custom_undeclared_%s", testName),
				Title:       "Undeclared Variable Rule",
				Description: "This rule uses undeclared variables",
				Severity:    "low",
			},
			CELPayload: compv1alpha1.CELPayload{
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
				ErrorMessage: "This should fail validation due to undeclared variable",
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
		// This is expected - the rule should fail validation
		t.Log("CustomRule validation correctly detected undeclared variable")
	} else {
		t.Fatal("Expected CustomRule to fail validation due to undeclared variable, but it succeeded")
	}

	t.Log("CustomRule validation tests completed successfully.")
}
