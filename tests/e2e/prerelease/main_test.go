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
