package prerelease_e2e

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// TestKubeletConfigAutoRemediation (test cases 46100, 46302, 54323, 66793) tests that
// auto-remediation properly updates an existing KubeletConfig object with incorrect
// tlsCipherSuites configuration. This test validates:
// 1. A KubeletConfig with insecure cipher suites is created and applied to nodes
// 2. Auto-remediation updates the KubeletConfig with secure cipher suites
// 3. The kubelet-configure-tls-cipher-suites rule passes after remediation
func TestKubeletConfigAutoRemediation(t *testing.T) {
	f := framework.Global

	// Test configuration
	kubeletConfigName := "test-kubelet-tls-cipher"
	machineConfigPoolName := "worker"
	bindingName := framework.GetObjNameFromTest(t)
	tailoredProfileName := framework.GetObjNameFromTest(t) + "-tp"

	// Expected cipher suite value after remediation
	expectedCipher := "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"

	// Cleanup function to remove test resources
	defer func() {
		t.Log("Cleaning up test resources")

		// Delete scan binding
		ssb := &compv1alpha1.ScanSettingBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      bindingName,
				Namespace: f.OperatorNamespace,
			},
		}
		err := f.Client.Delete(context.TODO(), ssb)
		if err != nil && !apierrors.IsNotFound(err) {
			t.Logf("Warning: Failed to delete scan binding: %s", err)
		}

		// Wait for scan cleanup
		err = f.WaitForScanCleanup()
		if err != nil {
			t.Logf("Warning: Failed to wait for scan cleanup: %s", err)
		}

		// Delete TailoredProfile
		tp := &compv1alpha1.TailoredProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:      tailoredProfileName,
				Namespace: f.OperatorNamespace,
			},
		}
		err = f.Client.Delete(context.TODO(), tp)
		if err != nil && !apierrors.IsNotFound(err) {
			t.Logf("Warning: Failed to delete tailored profile: %s", err)
		}

		// Delete KubeletConfig
		framework.DeleteKubeletConfig(f, kubeletConfigName)

		// Wait for MachineConfigPool to stabilize after cleanup
		time.Sleep(30 * time.Second)
		err = framework.WaitForMachineConfigPoolUpdate(f, machineConfigPoolName)
		if err != nil {
			t.Logf("Warning: Failed to wait for MachineConfigPool after cleanup: %s", err)
		}
	}()

	// Step 1: Create a KubeletConfig with insecure tlsCipherSuites
	t.Logf("Creating KubeletConfig '%s' with insecure tlsCipherSuites", kubeletConfigName)
	err := framework.CreateKubeletConfigWithInsecureCiphers(f, kubeletConfigName, machineConfigPoolName)
	if err != nil {
		t.Fatalf("Failed to create KubeletConfig: %s", err)
	}

	// Wait for KubeletConfig to be applied
	time.Sleep(10 * time.Second)

	// Verify initial KubeletConfig state (insecure ciphers)
	initialCiphers, err := framework.GetKubeletConfigCiphers(f, kubeletConfigName)
	if err != nil {
		t.Fatalf("Failed to get initial KubeletConfig ciphers: %s", err)
	}

	if len(initialCiphers) == 0 {
		t.Fatal("Expected insecure tlsCipherSuites but found empty list")
	}
	t.Logf("Verified: KubeletConfig has insecure tlsCipherSuites initially: %v", initialCiphers)

	// Wait for MachineConfigPool to apply the insecure KubeletConfig to nodes
	t.Logf("Waiting for MachineConfigPool '%s' to apply insecure KubeletConfig to nodes (this may take 10-20 minutes)", machineConfigPoolName)
	err = framework.WaitForMachineConfigPoolUpdate(f, machineConfigPoolName)
	if err != nil {
		t.Fatalf("Failed to wait for MachineConfigPool to apply KubeletConfig: %s", err)
	}
	t.Log("MachineConfigPool updated - nodes now have insecure tlsCipherSuites, scan should detect FAIL")

	// Step 2: Create a tailored profile with CIS kubelet rules and auto-apply enabled
	t.Log("Creating tailored profile for CIS with kubelet TLS cipher rules")
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tailoredProfileName,
			Namespace: f.OperatorNamespace,
			Annotations: map[string]string{
				"compliance.openshift.io/product-type": "Node",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "KubeletConfig Auto-Remediation Test Profile",
			Description: "Test profile for validating KubeletConfig auto-remediation (test cases 46100, 46302, 54323, 66793)",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{Name: "ocp4-kubelet-configure-tls-cipher-suites"},
			},
		},
	}
	err = f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatalf("Failed to create tailored profile: %s", err)
	}

	// Wait for TailoredProfile to be ready
	err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tailoredProfileName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatalf("Failed waiting for TailoredProfile to be ready: %s", err)
	}

	// Step 3: Create scan binding with auto-apply remediations
	t.Log("Creating scan binding with auto-apply remediations enabled")
	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     tailoredProfileName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default-auto-apply",
		},
	}
	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatalf("Failed to create scan binding: %s", err)
	}

	// When using SSB with TailoredProfile, the scan has same name as the TP
	scanName := tailoredProfileName

	// Step 4: Wait for compliance suite to complete
	t.Log("Waiting for compliance suite to complete first scan")
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatalf("Failed to wait for compliance suite: %s", err)
	}

	// Get initial scan results
	initialResults := make(map[string]compv1alpha1.ComplianceCheckStatus)
	err = framework.GetCheckResultsFromScan(f, scanName, initialResults)
	if err != nil {
		t.Fatalf("Failed to get initial scan results: %s", err)
	}

	// Step 5: Wait for auto-remediations to be applied
	t.Log("Waiting for auto-remediations to be applied")
	time.Sleep(30 * time.Second)

	err = framework.WaitForRemediationsToBeApplied(f, bindingName)
	if err != nil {
		t.Fatalf("Failed waiting for remediations to be applied: %s", err)
	}

	// Step 6: Wait for MachineConfigPool to update after remediation
	t.Logf("Waiting for MachineConfigPool '%s' to update after remediation", machineConfigPoolName)
	err = framework.WaitForMachineConfigPoolUpdate(f, machineConfigPoolName)
	if err != nil {
		t.Fatalf("Failed to wait for MachineConfigPool: %s", err)
	}

	// Step 7: Verify KubeletConfig was updated with correct ciphers
	t.Log("Verifying KubeletConfig was updated with correct TLS cipher suites")
	updatedCiphers, err := framework.GetKubeletConfigCiphers(f, kubeletConfigName)
	if err != nil {
		t.Fatalf("Failed to get updated KubeletConfig ciphers: %s", err)
	}

	if len(updatedCiphers) == 0 {
		t.Fatal("KubeletConfig tlsCipherSuites is still empty after auto-remediation")
	}

	// Check that insecure ciphers were replaced
	hasInsecureCipher := false
	for _, cipher := range updatedCiphers {
		if cipher == "TLS_RSA_WITH_AES_128_GCM_SHA256" || cipher == "TLS_RSA_WITH_AES_256_CBC_SHA" {
			hasInsecureCipher = true
			break
		}
	}
	if hasInsecureCipher {
		t.Fatalf("KubeletConfig still contains insecure ciphers after remediation: %v", updatedCiphers)
	}

	// Check if expected cipher is present
	cipherFound := false
	for _, cipher := range updatedCiphers {
		if cipher == expectedCipher {
			cipherFound = true
			break
		}
	}

	if !cipherFound {
		t.Fatalf("Expected cipher '%s' not found in KubeletConfig. Found: %v", expectedCipher, updatedCiphers)
	}
	t.Logf("SUCCESS: KubeletConfig updated with correct ciphers: %v", updatedCiphers)

	// Step 8: Trigger rescan to verify rules pass
	t.Log("Triggering rescan to verify rules pass after remediation")
	err = f.RescanSuite(bindingName, f.OperatorNamespace)
	if err != nil {
		t.Fatalf("Failed to trigger rescan: %s", err)
	}

	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatalf("Failed to wait for rescan: %s", err)
	}

	// Step 9: Verify final scan results
	finalResults := make(map[string]compv1alpha1.ComplianceCheckStatus)
	err = framework.GetCheckResultsFromScan(f, scanName, finalResults)
	if err != nil {
		t.Fatalf("Failed to get final scan results: %s", err)
	}

	// Verify critical rules pass
	criticalRules := []string{
		"kubelet-configure-tls-cipher-suites",
	}

	var failures []string
	for _, ruleName := range criticalRules {
		// Find the check result by partial name match
		found := false
		for checkName, status := range finalResults {
			if strings.Contains(checkName, ruleName) {
				if status != compv1alpha1.CheckResultPass {
					failures = append(failures,
						fmt.Sprintf("Rule %s: expected PASS, got %s", ruleName, status))
				} else {
					t.Logf("✓ Rule %s: PASS", ruleName)
					found = true
				}
				break
			}
		}
		if !found {
			failures = append(failures, fmt.Sprintf("Rule %s not found in scan results", ruleName))
		}
	}

	if len(failures) > 0 {
		t.Fatalf("KubeletConfig auto-remediation test failed:\n%s", strings.Join(failures, "\n"))
	}

	t.Log("✓ KubeletConfig auto-remediation test passed successfully")
}
