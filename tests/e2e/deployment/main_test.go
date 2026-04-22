package deployment_e2e

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var brokenContentImagePath string
var contentImagePath string

func TestMain(m *testing.M) {
	f := framework.NewFramework()
	err := f.SetUp()
	if err != nil {
		log.Fatal(err)
	}

	contentImagePath = os.Getenv("CONTENT_IMAGE")
	if contentImagePath == "" {
		fmt.Println("Please set the 'CONTENT_IMAGE' environment variable")
		os.Exit(1)
	}

	brokenContentImagePath = os.Getenv("BROKEN_CONTENT_IMAGE")

	if brokenContentImagePath == "" {
		fmt.Println("Please set the 'BROKEN_CONTENT_IMAGE' environment variable")
		os.Exit(1)
	}
	exitCode := m.Run()
	if exitCode == 0 || (exitCode > 0 && f.CleanUpOnError()) {
		if err = f.TearDown(); err != nil {
			log.Fatal(err)
		}
	}
	os.Exit(exitCode)
}

func TestServiceMonitoringMetricsTarget(t *testing.T) {
	t.Parallel()
	f := framework.Global

	err := f.SetupRBACForMetricsTest()
	if err != nil {
		t.Fatalf("failed to create service account: %s", err)
	}
	defer f.CleanUpRBACForMetricsTest()

	metricsTargets, err := f.WaitForPrometheusMetricTargets()
	if err != nil {
		t.Fatalf("failed to get prometheus metric targets: %s", err)
	}

	expectedMetricsCount := 2

	err = f.AssertServiceMonitoringMetricsTarget(metricsTargets, expectedMetricsCount)
	if err != nil {
		t.Fatalf("failed to assert metrics target: %s", err)
	}
}

func TestResultServerHTTPVersion(t *testing.T) {
	t.Parallel()
	f := framework.Global
	endpoints := []string{
		fmt.Sprintf("https://metrics.%s.svc:8585/metrics-co", f.OperatorNamespace),
		fmt.Sprintf("http://metrics.%s.svc:8383/metrics", f.OperatorNamespace),
	}

	expectedHTTPVersion := "HTTP/1.1"
	for _, endpoint := range endpoints {
		err := f.AssertMetricsEndpointUsesHTTPVersion(endpoint, expectedHTTPVersion)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestProfileBundleDefaultIsKept(t *testing.T) {
	f := framework.Global
	var (
		otherImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_baseline")
		bctx       = context.Background()
	)

	ocpPb, err := f.GetReadyProfileBundle("ocp4", f.OperatorNamespace)
	if err != nil {
		t.Fatalf("failed to get ocp4 ProfileBundle: %s", err)
	}

	origImage := ocpPb.Spec.ContentImage

	ocpPbCopy := ocpPb.DeepCopy()
	ocpPbCopy.Spec.ContentImage = otherImage
	ocpPbCopy.Spec.ContentFile = framework.RhcosContentFile
	if updateErr := f.Client.Update(bctx, ocpPbCopy); updateErr != nil {
		t.Fatalf("failed to update default ocp4 profile: %s", err)
	}

	if err := f.WaitForProfileBundleStatus("ocp4", compv1alpha1.DataStreamPending); err != nil {
		t.Fatalf("ocp4 update didn't trigger a PENDING state: %s", err)
	}

	// Now wait for the processing to finish
	if err := f.WaitForProfileBundleStatus("ocp4", compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("ocp4 update didn't trigger a PENDING state: %s", err)
	}

	// Delete compliance operator pods
	// This will trigger a reconciliation of the profile bundle
	// This is what would happen on an operator update.

	inNs := client.InNamespace(f.OperatorNamespace)
	withLabel := client.MatchingLabels{
		"name": "compliance-operator",
	}
	if err := f.Client.DeleteAllOf(bctx, &corev1.Pod{}, inNs, withLabel); err != nil {
		t.Fatalf("failed to delete compliance-operator pods: %s", err)
	}

	// Wait for the operator deletion to happen
	time.Sleep(framework.RetryInterval)

	err = f.WaitForDeployment("compliance-operator", 1, framework.RetryInterval, framework.Timeout)
	if err != nil {
		t.Fatalf("failed waiting for compliance-operator to come back up: %s", err)
	}

	var lastErr error
	pbkey := types.NamespacedName{Name: "ocp4", Namespace: f.OperatorNamespace}
	timeouterr := wait.Poll(framework.RetryInterval, framework.Timeout, func() (bool, error) {
		pb := &compv1alpha1.ProfileBundle{}
		if lastErr := f.Client.Get(bctx, pbkey, pb); lastErr != nil {
			log.Printf("error getting ocp4 PB. Retrying: %s\n", err)
			return false, nil
		}
		if pb.Spec.ContentImage != origImage {
			log.Printf("ProfileBundle ContentImage not updated yet: Got %s - Expected %s\n", pb.Spec.ContentImage, origImage)
			return false, nil
		}
		log.Printf("ProfileBundle ContentImage up-to-date\n")
		return true, nil
	})
	if lastErr != nil {
		t.Fatalf("failed waiting for ProfileBundle to update: %s", lastErr)
	}
	if timeouterr != nil {
		t.Fatalf("timed out waiting for ProfileBundle to update: %s", timeouterr)
	}

	_, err = f.GetReadyProfileBundle("ocp4", f.OperatorNamespace)
	if err != nil {
		t.Fatalf("error getting valid and up-to-date PB: %s", err)
	}
}
