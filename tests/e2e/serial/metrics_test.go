package serial_e2e

import (
	"context"
	"fmt"
	"log"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
)

// TestComplianceStateMetricSurvivesOperatorRestart is a regression test for
// CMP-4373. The compliance_operator_compliance_state gauge lives only in the
// operator's in-memory Prometheus registry. Before the fix it was written only
// on a scan phase transition and was never re-synced or cleaned up, so the
// series went missing after an operator restart and lingered after the suite
// was deleted.
//
// This test asserts the gauge:
//   - reports the suite result (NON-COMPLIANT = 1) once the scan is Done,
//   - is still present and correct after the operator is restarted (re-sync),
//   - is removed once the suite is deleted (cleanup).
//
// A NON-COMPLIANT suite is used on purpose: an absent series parses as 0, so a
// COMPLIANT suite (also 0) could not be distinguished from a missing one.
func TestComplianceStateMetricSurvivesOperatorRestart(t *testing.T) {
	f := framework.Global
	suiteName := "metric-state-restart-suite"
	scanName := fmt.Sprintf("%s-platform-scan", suiteName)

	if err := f.SetupRBACForMetricsTest(); err != nil {
		t.Fatalf("failed to set up metrics RBAC: %s", err)
	}
	defer f.CleanUpRBACForMetricsTest()

	suite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ScanType:     compv1alpha1.ScanTypePlatform,
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_cis",
						Content:      framework.OcpContentFile,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
						},
					},
					Name: scanName,
				},
			},
		},
	}

	if err := f.Client.Create(context.TODO(), suite, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), suite)

	// Wait for the platform scan to finish NON-COMPLIANT.
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	stateMetric := fmt.Sprintf("compliance_operator_compliance_state{name=\"%s\"}", suiteName)

	// The gauge should report NON-COMPLIANT (1) before the restart.
	if err := assertComplianceStateMetricEventually(f, stateMetric, 1); err != nil {
		t.Fatalf("before restart: %s", err)
	}

	// Restart the operator. Before the fix, the in-memory gauge is lost on
	// restart and never re-emitted for an already-Done suite.
	if err := f.RestartComplianceOperator(); err != nil {
		t.Fatal(err)
	}

	// The gauge must be re-synced from the suite status after the restart.
	if err := assertComplianceStateMetricEventually(f, stateMetric, 1); err != nil {
		t.Fatalf("after restart (re-sync regression): %s", err)
	}

	// Deleting the suite must remove the series; otherwise the stale
	// NON-COMPLIANT value (1) lingers and keeps firing alerts. An absent
	// series parses as 0.
	if err := f.Client.Delete(context.TODO(), suite); err != nil {
		t.Fatal(err)
	}
	if err := assertComplianceStateMetricEventually(f, stateMetric, 0); err != nil {
		t.Fatalf("after delete (cleanup regression): %s", err)
	}
}

// assertComplianceStateMetricEventually polls the metrics endpoint until the
// given compliance_state series reaches the expected value. An absent series
// parses as 0.
func assertComplianceStateMetricEventually(f *framework.Framework, metric string, expected int) error {
	var lastErr error
	pollErr := wait.PollImmediate(framework.RetryInterval, 5*time.Minute, func() (bool, error) {
		lastErr = framework.AssertEachMetric(f.OperatorNamespace, map[string]int{metric: expected})
		if lastErr != nil {
			log.Printf("waiting for metric %s to reach %d: %s", metric, expected, lastErr)
			return false, nil
		}
		return true, nil
	})
	if pollErr != nil {
		return fmt.Errorf("metric %s did not reach %d: %v (last error: %v)", metric, expected, pollErr, lastErr)
	}
	return nil
}
