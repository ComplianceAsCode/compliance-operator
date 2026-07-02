package upgrade_e2e

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	compsuitectrl "github.com/ComplianceAsCode/compliance-operator/pkg/controller/compliancesuite"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

// TestUpgradeScanSuspendResumeRerunner ports test case 37721/56351:
// - run ocp4-cis through custom ScanSetting/ScanSettingBinding,
// - upgrade compliance-operator to catalog source "compliance-operator",
// - verify rerunner CronJob behavior while suspending/resuming ScanSetting.
func TestUpgradeScanSuspendResumeRerunner(t *testing.T) {
	f := framework.Global

	arch, err := f.GetClusterArchitecture()
	if err != nil {
		t.Fatalf("cluster architecture: %v", err)
	}
	if arch == "arm64" || arch == "multi" {
		t.Skipf("skipping on architecture %s (upstream parity)", arch)
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

	scanSettingName := framework.GetObjNameFromTest(t) + "-scansetting"
	scanSettingSchedule := "*/3 * * * *"
	scanSetting := &compv1alpha1.ScanSetting{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingName,
			Namespace: f.OperatorNamespace,
		},
		ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
			AutoApplyRemediations:  false,
			AutoUpdateRemediations: false,
			Schedule:               scanSettingSchedule,
			Suspend:                false,
		},
		ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
			RawResultStorage: compv1alpha1.RawResultStorageSettings{
				Size:     "2Gi",
				Rotation: 3,
			},
			Debug: true,
		},
		Roles: []string{"master", "worker"},
	}
	if err := f.Client.Create(context.TODO(), scanSetting, nil); err != nil {
		t.Fatalf("create ScanSetting %s: %v", scanSettingName, err)
	}
	defer func() {
		if err := f.Client.Delete(context.TODO(), scanSetting); err != nil && !apierrors.IsNotFound(err) {
			t.Logf("cleanup ScanSetting %s: %v", scanSettingName, err)
		}
	}()

	ssbName := framework.GetObjNameFromTest(t) + "-binding"
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
			Name:     scanSettingName,
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

	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, ssbName, compv1alpha1.PhaseRunning, compv1alpha1.ResultNotAvailable); err != nil {
		t.Fatalf("suite %s did not enter RUNNING before upgrade: %v", ssbName, err)
	}
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, ssbName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatalf("suite %s not DONE/NON-COMPLIANT before upgrade: %v", ssbName, err)
	}
	if err := f.WaitForCronJobWithSchedule(f.OperatorNamespace, ssbName, scanSettingSchedule); err != nil {
		t.Fatalf("rerunner cronjob %s schedule mismatch before upgrade: %v", ssbName, err)
	}

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
	if arch == "amd64" {
		if err := f.WaitForProfileBundleStatus("rhcos4", compv1alpha1.DataStreamValid); err != nil {
			t.Fatalf("rhcos4 profile bundle is not VALID: %v", err)
		}
	}

	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, ssbName, compv1alpha1.PhaseRunning, compv1alpha1.ResultNotAvailable); err != nil {
		t.Fatalf("suite %s did not enter RUNNING after upgrade: %v", ssbName, err)
	}
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, ssbName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatalf("suite %s not DONE/NON-COMPLIANT after first post-upgrade run: %v", ssbName, err)
	}

	rerunnerName := compsuitectrl.GetRerunnerName(ssbName)
	lastSuccessfulTime, err := f.WaitForCronJobLastSuccessfulTime(rerunnerName, 6*time.Minute)
	if err != nil {
		t.Fatalf("get baseline cronjob lastSuccessfulTime for %s: %v", rerunnerName, err)
	}

	if err := f.SetScanSettingSuspend(scanSettingName, true); err != nil {
		t.Fatalf("suspend ScanSetting %s: %v", scanSettingName, err)
	}
	if err := f.WaitForScanSettingBindingStatus(f.OperatorNamespace, ssbName, compv1alpha1.ScanSettingBindingPhaseSuspended); err != nil {
		t.Fatalf("ScanSettingBinding %s failed to suspend: %v", ssbName, err)
	}
	if err := f.AssertScanSettingBindingConditionIsSuspended(ssbName, f.OperatorNamespace); err != nil {
		t.Fatalf("ScanSettingBinding %s suspended condition mismatch: %v", ssbName, err)
	}
	if err := f.AssertCronJobIsSuspended(rerunnerName); err != nil {
		t.Fatalf("CronJob %s should be suspended: %v", rerunnerName, err)
	}
	lastSuccessfulTimeSuspended, err := f.GetCronJobLastSuccessfulTime(rerunnerName)
	if err != nil {
		t.Fatalf("get suspended cronjob lastSuccessfulTime for %s: %v", rerunnerName, err)
	}
	if lastSuccessfulTimeSuspended != lastSuccessfulTime {
		t.Fatalf("expected suspended lastSuccessfulTime (%q) to equal baseline (%q)", lastSuccessfulTimeSuspended, lastSuccessfulTime)
	}

	if err := f.SetScanSettingSuspend(scanSettingName, false); err != nil {
		t.Fatalf("resume ScanSetting %s: %v", scanSettingName, err)
	}
	if err := f.WaitForScanSettingBindingStatus(f.OperatorNamespace, ssbName, compv1alpha1.ScanSettingBindingPhaseReady); err != nil {
		t.Fatalf("ScanSettingBinding %s failed to resume: %v", ssbName, err)
	}
	if err := f.AssertScanSettingBindingConditionIsReady(ssbName, f.OperatorNamespace); err != nil {
		t.Fatalf("ScanSettingBinding %s ready condition mismatch after resume: %v", ssbName, err)
	}
	if err := f.AssertCronJobIsNotSuspended(rerunnerName); err != nil {
		t.Fatalf("CronJob %s should be active after resume: %v", rerunnerName, err)
	}

	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, ssbName, compv1alpha1.PhaseRunning, compv1alpha1.ResultNotAvailable); err != nil {
		t.Fatalf("suite %s did not enter RUNNING after resume: %v", ssbName, err)
	}
	if err := f.WaitForSuiteScansStatusAnyResult(
		f.OperatorNamespace,
		ssbName,
		compv1alpha1.PhaseDone,
		compv1alpha1.ResultNonCompliant,
		compv1alpha1.ResultInconsistent,
	); err != nil {
		t.Fatalf("suite %s not DONE with allowed result after resume: %v", ssbName, err)
	}

	lastSuccessfulTimeResumed, err := f.WaitForCronJobLastSuccessfulTime(rerunnerName, 6*time.Minute)
	if err != nil {
		t.Fatalf("get resumed cronjob lastSuccessfulTime for %s: %v", rerunnerName, err)
	}
	if lastSuccessfulTimeResumed == lastSuccessfulTime {
		t.Fatalf("expected resumed lastSuccessfulTime to differ from baseline; both were %q", lastSuccessfulTime)
	}
}
