package upgrade_e2e

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestMain(m *testing.M) {
	f := framework.NewFramework()

	// Use with TEST_OPERATOR_NAMESPACE=openshift-compliance (or your install ns) when Compliance
	// Operator is already installed. Skips manifest deploy, CRD apply, e2e MCP, and TearDown.
	skipSetup := os.Getenv("E2E_SKIP_FRAMEWORK_SETUP") == "true"
	if skipSetup {
		if err := f.EnsureE2ESchemes(); err != nil {
			log.Fatalf("EnsureE2ESchemes: %v", err)
		}
	} else {
		if err := f.SetUp(); err != nil {
			log.Fatal(err)
		}
	}

	exitCode := m.Run()
	if !skipSetup && (exitCode == 0 || (exitCode > 0 && f.CleanUpOnError())) {
		if err := f.TearDown(); err != nil {
			log.Fatal(err)
		}
	}
	os.Exit(exitCode)
}

// TestUpgradeTargetDownNotRaised ports test case 56353: after an optional OLM upgrade to a newer
// compliance-operator CSV from the compliance-operator catalog, run ocp4-cis via ScanSettingBinding,
// verify metrics, PrometheusRule, Alertmanager non-compliance alert (label name + description), and assert ALERTS for the
// operator namespace does not contain TargetDown.
func TestUpgradeTargetDownNotRaised(t *testing.T) {
	f := framework.Global

	arch := f.ClusterArchitecture()
	if arch == framework.ArchARM64 || arch == framework.ArchMULTI {
		t.Skipf("skipping on architecture %s (upstream parity)", arch.String())
	}

	upgradable, err := f.IsComplianceOperatorUpgradable("compliance-operator", "stable")
	if err != nil {
		t.Fatalf("check upgradable: %v", err)
	}
	if !upgradable {
		t.Skip("compliance-operator stable channel has no newer CSV than installed")
	}

	oldCSV, err := f.GetInstalledComplianceOperatorCSV()
	if err != nil {
		t.Fatalf("get installed CSV: %v", err)
	}
	t.Logf("Old CSV version: %v", oldCSV)
	if err := f.PatchComplianceOperatorSubscriptionSource("compliance-operator"); err != nil {
		t.Fatalf("patch subscription source: %v", err)
	}
	time.Sleep(10 * time.Second)

	if err := f.WaitForComplianceOperatorCSVUpgrade(oldCSV); err != nil {
		t.Fatalf("wait for upgraded CSV: %v", err)
	}
	if err := f.AssertComplianceOperatorPodRunning(); err != nil {
		t.Fatalf("compliance-operator pod is not running: %v", err)
	}
	if err := f.WaitForProfileBundleStatus("ocp4", compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("ocp4 profile bundle is not VALID: %v", err)
	}
	if arch == framework.ArchAMD64 {
		if err := f.WaitForProfileBundleStatus("rhcos4", compv1alpha1.DataStreamValid); err != nil {
			t.Fatalf("rhcos4 profile bundle is not VALID: %v", err)
		}
	}

	if err := f.SetupRBACForMetricsTest(); err != nil {
		if errors.Is(err, framework.ErrAlertManagerRBACUnavailable) {
			t.Skipf("Skipping test: %v", err)
		}
		t.Fatalf("setup metrics RBAC: %v", err)
	}
	defer f.CleanUpRBACForMetricsTest()

	ssbName := framework.GetObjNameFromTest(t) + "-upg-metrics"
	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ssbName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     "ocp4-cis",
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
	if err := f.Client.Create(context.TODO(), ssb, nil); err != nil {
		t.Fatalf("create ScanSettingBinding %s: %v", ssbName, err)
	}
	defer func() {
		if err := f.DeleteScanSettingBindingAndWaitForCleanup(ssb); err != nil {
			t.Logf("cleanup ScanSettingBinding %s: %v", ssbName, err)
		}
	}()

	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, ssbName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatalf("suite %s not DONE/NON-COMPLIANT: %v", ssbName, err)
	}

	if err := f.AssertMetricsContain(ssbName); err != nil {
		t.Fatalf("metrics assertions: %v", err)
	}
	if err := f.AssertPrometheusRule(); err != nil {
		t.Fatalf("prometheusrule assertions: %v", err)
	}
	want := fmt.Sprintf("The compliance suite %s returned as NON-COMPLIANT, ERROR, or INCONSISTENT", ssbName)
	if err := f.AssertAlertManagerAlertExists(ssbName, want, 300*time.Second); err != nil {
		t.Fatalf("alertmanager alert: %v", err)
	}
	if err := f.WaitForAlertAbsent("TargetDown", 180*time.Second); err != nil {
		t.Fatalf("TargetDown absence check: %v", err)
	}
}
