package prerelease_e2e

import (
	"context"
	"fmt"
	"log"
	"math"
	"os"
	"testing"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
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

// Test TestResourceRequestsQuotaVariable validates that setting
// ocp4-var-resource-requests-quota-per-project-exempt-regex to all non-control
// namespaces makes quota checks PASS for tailored profiles extending ocp4-stig
// and ocp4-moderate.
func TestResourceRequestsQuotaVariable(t *testing.T) {
	f := framework.Global
	arch := f.ClusterArchitecture()
	if arch == framework.ArchARM64 || arch == framework.ArchMULTI || arch == framework.ArchS390X {
		t.Skipf("skipping on architecture %s (upstream parity)", arch.String())
	}

	base := framework.GetObjNameFromTest(t)
	nsTest1 := base + "-ns1"
	nsTest2 := base + "-ns2"
	tpStigName := base + "-stig"
	tpModerateName := base + "-moderate"
	ssbStigName := base + "-ssb-stig"
	ssbModerateName := base + "-ssb-moderate"

	for _, ns := range []string{nsTest1, nsTest2} {
		_, err := f.KubeClient.CoreV1().Namespaces().Create(context.TODO(), &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: ns},
		}, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("create namespace %s: %v", ns, err)
		}
		defer f.KubeClient.CoreV1().Namespaces().Delete(context.TODO(), ns, metav1.DeleteOptions{})
	}

	exemptRegex, err := f.NonControlNamespacesRegex()
	if err != nil {
		t.Fatalf("compute non-control namespaces regex: %v", err)
	}
	t.Logf("Computed exempt regex with %d chars", len(exemptRegex))

	tpStig := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpStigName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Extends:     "ocp4-stig",
			Title:       "Quota exempt regex",
			Description: "Ported from extended test case 76105",
			SetValues: []compv1alpha1.VariableValueSpec{
				{
					Name:      "ocp4-var-resource-requests-quota-per-project-exempt-regex",
					Rationale: "test",
					Value:     exemptRegex,
				},
			},
		},
	}
	tpModerate := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpModerateName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Extends:     "ocp4-moderate",
			Title:       "Quota exempt regex",
			Description: "Ported from extended test case 76105",
			SetValues: []compv1alpha1.VariableValueSpec{
				{
					Name:      "ocp4-var-resource-requests-quota-per-project-exempt-regex",
					Rationale: "test",
					Value:     exemptRegex,
				},
			},
		},
	}
	if err := f.Client.Create(context.TODO(), tpStig, nil); err != nil {
		t.Fatalf("create TailoredProfile %s: %v", tpStig.Name, err)
	}
	defer f.Client.Delete(context.TODO(), tpStig)
	if err := f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpStig.Name, compv1alpha1.TailoredProfileStateReady); err != nil {
		t.Fatalf("wait TailoredProfile %s ready: %v", tpStig.Name, err)
	}

	if err := f.Client.Create(context.TODO(), tpModerate, nil); err != nil {
		t.Fatalf("create TailoredProfile %s: %v", tpModerate.Name, err)
	}
	defer f.Client.Delete(context.TODO(), tpModerate)
	if err := f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpModerate.Name, compv1alpha1.TailoredProfileStateReady); err != nil {
		t.Fatalf("wait TailoredProfile %s ready: %v", tpModerate.Name, err)
	}

	ssbStig := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ssbStigName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     tpStigName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}
	ssbModerate := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ssbModerateName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     tpModerateName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}
	if err := f.Client.Create(context.TODO(), ssbStig, nil); err != nil {
		t.Fatalf("create ScanSettingBinding %s: %v", ssbStig.Name, err)
	}
	defer func() {
		if err := f.DeleteScanSettingBindingAndWaitForCleanup(ssbStig); err != nil {
			t.Logf("cleanup ScanSettingBinding %s failed: %v", ssbStig.Name, err)
		}
	}()

	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, ssbStig.Name, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	if err := f.Client.Create(context.TODO(), ssbModerate, nil); err != nil {
		t.Fatalf("create ScanSettingBinding %s: %v", ssbModerate.Name, err)
	}
	defer func() {
		if err := f.DeleteScanSettingBindingAndWaitForCleanup(ssbModerate); err != nil {
			t.Logf("cleanup ScanSettingBinding %s failed: %v", ssbModerate.Name, err)
		}
	}()

	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, ssbModerate.Name, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	for _, suiteName := range []string{ssbStigName, ssbModerateName} {
		suite := &compv1alpha1.ComplianceSuite{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: suiteName, Namespace: f.OperatorNamespace}, suite); err != nil {
			t.Fatalf("get suite %s: %v", suiteName, err)
		}
		for _, scanStatus := range suite.Status.ScanStatuses {
			exitCode, _, err := f.GetScanExitCodeAndErrorMsg(scanStatus.Name, f.OperatorNamespace)
			if err != nil {
				t.Fatalf("get exit code for scan %s: %v", scanStatus.Name, err)
			}
			if exitCode != "2" {
				t.Fatalf("scan %s: expected exit-code 2, got %s", scanStatus.Name, exitCode)
			}
		}
	}

	stigCheckName := fmt.Sprintf("%s-resource-requests-quota-per-project", tpStigName)
	if err := f.WaitForCheckResultStatus(stigCheckName, compv1alpha1.CheckResultPass); err != nil {
		t.Fatalf("check %s did not become PASS: %v", stigCheckName, err)
	}

	moderateCheckName := fmt.Sprintf("%s-resource-requests-quota", tpModerateName)
	if err := f.WaitForCheckResultStatus(moderateCheckName, compv1alpha1.CheckResultPass); err != nil {
		t.Fatalf("check %s did not become PASS: %v", moderateCheckName, err)
	}
}

// TestOperatorMemoryWithManyNamespaces verifies that the compliance operator pod
// does not experience excessive memory growth when there are many namespaces in the cluster.
// This test creates 600 namespaces, runs a compliance scan, and ensures memory usage
// doesn't increase by more than 30Mi, confirming the operator won't be OOMKilled.
func TestOperatorMemoryWithManyNamespaces(t *testing.T) {
	f := framework.Global
	const nsCount = 600
	const memThresholdMi = 30.0
	const testNsPrefix = "oom-test-"

	// Get the compliance operator pod before the test
	operatorPod, err := f.GetComplianceOperatorPod()
	if err != nil {
		t.Fatalf("Failed to get compliance operator pod: %v", err)
	}

	// Measure initial memory usage
	memBefore, err := f.GetPodMemoryUsageMi(operatorPod)
	if err != nil {
		t.Fatalf("Failed to get initial memory usage: %v", err)
	}
	t.Logf("Memory usage before creating %d namespaces: %.2f Mi", nsCount, memBefore)

	// Create test namespaces
	createdNamespaces := f.CreateTestNamespaces(t, nsCount, testNsPrefix)
	defer f.CleanupTestNamespaces(t, createdNamespaces)

	// Create a scan to trigger operator activity with many namespaces
	scanName := "oom-test-scan"
	suite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: false,
			},
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					Name: fmt.Sprintf("%s-workers-scan", scanName),
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						Profile: "xccdf_org.ssgproject.content_profile_cis",
						Content: framework.OcpContentFile,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							RawResultStorage: compv1alpha1.RawResultStorageSettings{
								Size: "2Gi",
							},
							Debug: true,
						},
					},
				},
				{
					Name: fmt.Sprintf("%s-workers-node-scan", scanName),
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						Profile: "xccdf_org.ssgproject.content_profile_cis-node",
						Content: framework.OcpContentFile,
						NodeSelector: map[string]string{
							"node-role.kubernetes.io/worker": "",
						},
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							RawResultStorage: compv1alpha1.RawResultStorageSettings{
								Size: "2Gi",
							},
							Debug: true,
						},
					},
				},
			},
		},
	}
	err = f.Client.Create(context.TODO(), suite, nil)
	if err != nil {
		t.Fatalf("Failed to create compliance suite: %v", err)
	}
	defer f.Client.Delete(context.TODO(), suite)

	// Wait for scan to complete
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatalf("Failed waiting for compliance suite to complete: %v", err)
	}

	// Measure memory usage after creating namespaces and running scan
	operatorPod, err = f.GetComplianceOperatorPod()
	if err != nil {
		t.Fatalf("Failed to get compliance operator pod after scan: %v", err)
	}

	memAfter, err := f.GetPodMemoryUsageMi(operatorPod)
	if err != nil {
		t.Fatalf("Failed to get memory usage after scan: %v", err)
	}
	t.Logf("Memory usage after creating %d namespaces: %.2f Mi", nsCount, memAfter)

	// Check memory increase
	memIncrease := math.Abs(memAfter - memBefore)
	t.Logf("Memory increase: %.2f Mi (threshold: %.2f Mi)", memIncrease, memThresholdMi)

	if memIncrease > memThresholdMi {
		t.Fatalf("Memory usage increased by %.2f Mi, exceeding threshold of %.2f Mi. "+
			"This suggests potential OOM issues with many namespaces.", memIncrease, memThresholdMi)
	}

	t.Logf("Test completed successfully - no excessive memory growth detected")
}
