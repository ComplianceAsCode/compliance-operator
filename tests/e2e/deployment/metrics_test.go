package deployment_e2e

import (
	"context"
	"errors"
	"fmt"
	"log"
	"testing"
	"time"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
)

// TestErrorMetricsPrometheusRule uses a suite intended to reach phase DONE, result ERROR:
// real content image with a non-existent content path so OpenSCAP cannot load the data stream
// and the scan ends DONE/ERROR.
func TestErrorMetricsPrometheusRule(t *testing.T) {
	f := framework.Global

	// The operator only gets scraped by cluster monitoring, and only ships the
	// PrometheusRule that the alert assertion below checks for, when the
	// namespace opts in and the metrics Service exists. Both are prerequisites
	// for the rest of this test, not things it's trying to verify, so fail fast
	// with a clear reason instead of timing out later on a metrics scrape.
	ns := &corev1.Namespace{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: f.OperatorNamespace}, ns); err != nil {
		t.Fatal(err)
	}
	if ns.Labels == nil || ns.Labels["openshift.io/cluster-monitoring"] != "true" {
		t.Fatalf("namespace %s does not have openshift.io/cluster-monitoring=true", f.OperatorNamespace)
	}
	metricsSvc := &corev1.Service{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: "metrics", Namespace: f.OperatorNamespace}, metricsSvc); err != nil {
		t.Fatal(err)
	}

	base := framework.GetObjNameFromTest(t)
	suiteName := base + "-test-suite"
	scanName := base + "-scan"
	selectWorkers := map[string]string{"node-role.kubernetes.io/worker": ""}

	// Content points at a file that doesn't exist in the image, so OpenSCAP
	// can never load a data stream to scan against. This deliberately drives
	// the scan to phase DONE, result ERROR - the condition this test exists
	// to exercise the metrics and alerting for.
	suite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: false,
			},
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					Name: scanName,
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      "this-file-does-not-exist.xml",
						ContentImage: contentImagePath,
						NodeSelector: selectWorkers,
					},
				},
			},
		},
	}

	if err := f.Client.Create(context.TODO(), suite, nil); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = f.Client.Delete(context.TODO(), suite)
	}()

	// Confirm the scan actually errors as intended before asserting anything
	// about the metrics/alerts it should produce - otherwise a failure below
	// could just as easily mean the scan never reached the ERROR state.
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultError); err != nil {
		t.Fatalf("suite %s did not reach DONE/ERROR: %v", suiteName, err)
	}

	// The operator increments a scan error counter and sets the suite's
	// compliance-state gauge to the ERROR value; both should show up the same
	// way they would for any other scan result.
	wantScanMetric := fmt.Sprintf(`compliance_operator_compliance_scan_status_total{name="%s",phase="DONE",result="ERROR"`, scanName)
	wantSuiteMetric := fmt.Sprintf(`compliance_operator_compliance_state{name="%s"}`, suiteName)
	if err := framework.WaitForMetricOutputContainsAll(
		f.OperatorNamespace,
		[]string{wantScanMetric, wantSuiteMetric},
		3*time.Minute,
		framework.RetryInterval,
	); err != nil {
		t.Fatalf("metrics scrape (same path as getMetricResults / TestSingleScanSucceeds style): %v", err)
	}

	// Beyond the raw metric, an ERROR result should also be surfaced as a
	// firing NonCompliant alert via the operator's PrometheusRule, which is
	// what actually pages someone rather than just incrementing a counter.
	if err := f.AssertPrometheusRule(); err != nil {
		t.Fatalf("PrometheusRule NonCompliant alert: %v", err)
	}
}

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

func TestPrometheusRuleComplianceAlert(t *testing.T) {
	f := framework.Global
	f.HoldScanLocks(t, "ocp4-pci-dss")
	defer f.CleanUpRBACForMetricsTest()

	bindingName := "pci-test"
	expectedAlertDescription := "The compliance suite pci-test returned as NON-COMPLIANT, ERROR, or INCONSISTENT"

	if err := f.SetupRBACForMetricsTest(); err != nil {
		if errors.Is(err, framework.ErrAlertManagerRBACUnavailable) {
			t.Skipf("Skipping test: %v", err)
		}
		t.Fatalf("failed to setup RBAC for metrics test: %s", err)
	}

	ns := &corev1.Namespace{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: f.OperatorNamespace}, ns); err != nil {
		t.Fatalf("failed to get namespace %s: %v", f.OperatorNamespace, err)
	}
	if ns.Labels == nil || ns.Labels["openshift.io/cluster-monitoring"] != "true" {
		t.Fatalf("namespace %s does not have openshift.io/cluster-monitoring=true", f.OperatorNamespace)
	}

	metricsSvc := &corev1.Service{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: "metrics", Namespace: f.OperatorNamespace}, metricsSvc); err != nil {
		t.Fatalf("failed to get metrics service: %v", err)
	}

	ssb := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     "ocp4-pci-dss",
				Kind:     "Profile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			Name:     "default",
			Kind:     "ScanSetting",
			APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}

	if err := f.Client.Create(context.TODO(), &ssb, nil); err != nil {
		t.Fatalf("failed to create ScanSettingBinding %s: %v", bindingName, err)
	}
	defer f.Client.Delete(context.TODO(), &ssb)

	if err := f.WaitForScanSettingBindingStatus(f.OperatorNamespace, bindingName, compv1alpha1.ScanSettingBindingPhaseReady); err != nil {
		t.Fatalf("ScanSettingBinding %s failed to become ready: %v", bindingName, err)
	}
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatalf("ComplianceSuite %s did not reach expected status: %v", bindingName, err)
	}
	if err := f.AssertAlertManagerAlertExists(bindingName, expectedAlertDescription, 5*time.Minute); err != nil {
		t.Fatalf("AlertManager alert check failed: %v", err)
	}
}
