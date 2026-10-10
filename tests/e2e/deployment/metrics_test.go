package deployment_e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
						ContentImage: "quay.io/compliance-operator/compliance-operator-content:latest",
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
	if err := f.AssertPrometheusRuleComplianceNonCompliantAlert(); err != nil {
		t.Fatalf("PrometheusRule NonCompliant alert: %v", err)
	}
}
