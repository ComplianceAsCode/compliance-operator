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
	configv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
		t.Fatalf("ocp4 update didn't trigger a VALID state: %s", err)
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
			log.Printf("error getting ocp4 PB. Retrying: %s\n", lastErr)
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

func TestOperatorHonorsClusterTLSProfile(t *testing.T) {
	f := framework.Global

	// Fetch the cluster APIServer resource.
	apiServer, err := f.GetClusterAPIServer()
	if err != nil {
		t.Fatalf("failed to get APIServer cluster resource: %s", err)
	}
	t.Logf("Original TLS adherence policy: %q", apiServer.Spec.TLSAdherence)

	// Skip if the cluster is older than OCP 4.22, which is the minimum
	// version that supports the tlsAdherence field on the APIServer resource.
	atLeast422, err := f.IsOCPVersionAtLeast(4, 22)
	if err != nil {
		t.Fatalf("failed to check cluster version: %s", err)
	}
	if !atLeast422 {
		t.Skip("cluster is older than OCP 4.22, tlsAdherence is not supported")
	}

	// Verify the metrics endpoint matches the current cluster TLS configuration.
	expectedTLSVersion := f.GetExpectedMinTLSVersion(apiServer)
	t.Logf("Expected minimum TLS version before change: %s", expectedTLSVersion)
	if err := f.AssertMetricsEndpointMinTLSVersion(expectedTLSVersion); err != nil {
		t.Fatalf("metrics endpoint TLS version check failed before change: %s", err)
	}

	// Record the current operator pod UID so we can detect when it restarts.
	operatorPods, err := f.GetOperatorPods()
	if err != nil {
		t.Fatalf("failed to get operator pods: %s", err)
	}
	if len(operatorPods) == 0 {
		t.Fatal("no operator pods found")
	}
	originalPodUID := operatorPods[0].UID
	t.Logf("Original operator pod UID: %s", originalPodUID)

	// Change the APIServer TLS configuration to strict adherence with the
	// Modern profile (TLS 1.3) so we can verify the operator enforces a
	// stricter TLS configuration when required.
	t.Log("Updating APIServer to strict adherence with Modern TLS profile")
	apiServer, err = f.GetClusterAPIServer()
	if err != nil {
		t.Fatalf("failed to get APIServer for update: %s", err)
	}
	apiServer.Spec.TLSAdherence = configv1.TLSAdherencePolicyStrictAllComponents
	apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
		Type:   configv1.TLSProfileModernType,
		Modern: &configv1.ModernTLSProfile{},
	}
	if err := f.Client.Update(context.TODO(), apiServer); err != nil {
		t.Fatalf("failed to update APIServer TLS configuration: %s", err)
	}

	// Wait for the operator pod to restart. The SecurityProfileWatcher
	// should detect the change and trigger a graceful shutdown.
	t.Log("Waiting for operator pod to restart after TLS profile change")
	if err := f.WaitForOperatorPodRestart(originalPodUID); err != nil {
		t.Fatalf("operator pod did not restart after TLS profile change: %s", err)
	}

	// Wait for the operator deployment to be fully available.
	if err := f.WaitForDeployment("compliance-operator", 1, framework.RetryInterval, framework.Timeout); err != nil {
		t.Fatalf("operator did not become ready after TLS profile change: %s", err)
	}

	// Verify the metrics endpoint now uses the updated TLS version.
	apiServer, err = f.GetClusterAPIServer()
	if err != nil {
		t.Fatalf("failed to get APIServer after update: %s", err)
	}
	expectedTLSVersion = f.GetExpectedMinTLSVersion(apiServer)
	t.Logf("Expected minimum TLS version after change: %s", expectedTLSVersion)
	if err := f.AssertMetricsEndpointMinTLSVersion(expectedTLSVersion); err != nil {
		t.Fatalf("metrics endpoint TLS version check failed after change: %s", err)
	}

	// Verify connections capped below the new minimum are rejected. This
	// proves the floor was actually raised — without it, a server that
	// silently ignores the profile still passes the positive check above
	// because curl negotiates the highest mutually supported version.
	t.Log("Verifying metrics endpoint rejects TLS 1.2 connections")
	if err := f.AssertMetricsEndpointRejectsTLSVersion("1.2"); err != nil {
		t.Fatalf("metrics endpoint accepted a TLS 1.2 connection despite Modern (TLS 1.3) profile: %s", err)
	}

	// Verify the result server also uses the updated TLS version by
	// creating a compliance scan and checking the result server endpoint.
	t.Log("Creating compliance scan to validate result server TLS configuration")
	tlsScanName := "tls-result-server-test"
	tlsScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tlsScanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			ContentImage: contentImagePath,
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				RawResultStorage: compv1alpha1.RawResultStorageSettings{
					Size: "2Gi",
				},
				Debug: true,
			},
		},
	}
	if err := f.Client.Create(context.TODO(), tlsScan, nil); err != nil {
		t.Fatalf("failed to create compliance scan for result server TLS test: %s", err)
	}
	defer f.Client.Delete(context.TODO(), tlsScan)

	t.Log("Waiting for result server deployment to become available")
	if err := f.WaitForDeployment(tlsScanName+"-rs", 1, framework.RetryInterval, framework.Timeout); err != nil {
		t.Fatalf("result server deployment did not become ready: %s", err)
	}

	t.Logf("Checking result server TLS version (expecting %s)", expectedTLSVersion)
	if err := f.AssertResultServerMinTLSVersion(tlsScanName, expectedTLSVersion); err != nil {
		t.Fatalf("result server TLS version check failed: %s", err)
	}

	// Same negative check for the result server — prove the floor was
	// raised by confirming TLS 1.2 handshakes are rejected.
	t.Log("Verifying result server rejects TLS 1.2 connections")
	if err := f.AssertResultServerRejectsTLSVersion(tlsScanName, "1.2"); err != nil {
		t.Fatalf("result server accepted a TLS 1.2 connection despite Modern (TLS 1.3) profile: %s", err)
	}

	t.Log("Waiting for compliance scan to complete")
	if err := f.WaitForScanStatus(f.OperatorNamespace, tlsScanName, compv1alpha1.PhaseDone); err != nil {
		t.Logf("scan did not reach Done phase: %s (non-fatal, TLS check already passed)", err)
	}
}
