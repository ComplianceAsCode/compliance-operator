package deployment_e2e

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	configv1 "github.com/openshift/api/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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

	exitCode := m.Run()
	if exitCode == 0 || (exitCode > 0 && f.CleanUpOnError()) {
		if err = f.TearDown(); err != nil {
			log.Fatal(err)
		}
	}
	os.Exit(exitCode)
}

func TestOperatorHonorsClusterTLSProfile(t *testing.T) {
	f := framework.Global

	// Fetch the cluster APIServer resource and save the original state for cleanup.
	apiServer, err := f.GetClusterAPIServer()
	if err != nil {
		t.Fatalf("failed to get APIServer cluster resource: %s", err)
	}
	originalTLSProfile := apiServer.Spec.TLSSecurityProfile
	originalAdherence := apiServer.Spec.TLSAdherence
	t.Logf("Original TLS adherence policy: %q", originalAdherence)

	// Skip if the cluster is older than OCP 4.22, which is the minimum
	// version that supports the tlsAdherence field on the APIServer resource.
	atLeast422, err := f.IsOCPVersionAtLeast(4, 22)
	if err != nil {
		t.Fatalf("failed to check cluster version: %s", err)
	}
	if !atLeast422 {
		t.Skip("cluster is older than OCP 4.22, tlsAdherence is not supported")
	}

	// Restore original APIServer TLS configuration when the test completes.
	defer func() {
		t.Log("Restoring original APIServer TLS configuration")
		apiServer, err := f.GetClusterAPIServer()
		if err != nil {
			t.Fatalf("failed to get APIServer for cleanup: %s", err)
		}
		apiServer.Spec.TLSSecurityProfile = originalTLSProfile
		apiServer.Spec.TLSAdherence = originalAdherence
		if err := f.Client.Update(context.TODO(), apiServer); err != nil {
			t.Fatalf("failed to restore APIServer TLS configuration: %s", err)
		}
	}()

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

	t.Log("Waiting for compliance scan to complete")
	if err := f.WaitForScanStatus(f.OperatorNamespace, tlsScanName, compv1alpha1.PhaseDone); err != nil {
		t.Logf("scan did not reach Done phase: %s (non-fatal, TLS check already passed)", err)
	}
}
