package upgrade_e2e

import (
	"context"
<<<<<<< HEAD
	"errors"
	"fmt"
=======
>>>>>>> 49d3cdedd (moved upgrade test to a seperate suite)
	"log"
	"os"
	"testing"
	"time"

<<<<<<< HEAD
	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	compsuitectrl "github.com/ComplianceAsCode/compliance-operator/pkg/controller/compliancesuite"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
=======
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	apiv1alpha1 "github.com/operator-framework/api/pkg/operators/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
>>>>>>> 49d3cdedd (moved upgrade test to a seperate suite)
)

func TestMain(m *testing.M) {
	f := framework.NewFramework()
<<<<<<< HEAD

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
=======
	err := f.SetUp()
	if err != nil {
		log.Fatal(err)
	}

	// Upgrade tests don't require content images like scan tests do
	// They work with the operator installation from OLM

	exitCode := m.Run()
	if exitCode == 0 || (exitCode > 0 && f.CleanUpOnError()) {
		if err = f.TearDown(); err != nil {
>>>>>>> 49d3cdedd (moved upgrade test to a seperate suite)
			log.Fatal(err)
		}
	}
	os.Exit(exitCode)
}

<<<<<<< HEAD
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

// TestUpgradeScanSuspendResumeRerunner ports test case 37721/56351:
// - run ocp4-cis through custom ScanSetting/ScanSettingBinding,
// - upgrade compliance-operator to catalog source "compliance-operator",
// - verify rerunner CronJob behavior while suspending/resuming ScanSetting.
func TestUpgradeScanSuspendResumeRerunner(t *testing.T) {
	f := framework.Global

	arch := f.ClusterArchitecture()
	if arch == framework.ArchARM64 || arch == framework.ArchMULTI {
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
	if arch == framework.ArchAMD64 {
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
	lastSuccessfulTime, err := f.WaitForCronJobLastSuccessfulTimeChanged(rerunnerName, "", 6*time.Minute)
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

	lastSuccessfulTimeResumed, err := f.WaitForCronJobLastSuccessfulTimeChanged(rerunnerName, lastSuccessfulTime, 6*time.Minute)
	if err != nil {
		t.Fatalf("get resumed cronjob lastSuccessfulTime for %s: %v", rerunnerName, err)
	}
	t.Logf("resumed cronjob lastSuccessfulTime changed from %q to %q", lastSuccessfulTime, lastSuccessfulTimeResumed)
=======
func TestOperatorUpgradeResourcesAndMCPStability(t *testing.T) {
	// Check if upgrade testing is configured
	upgradeCatalogImage := os.Getenv("UPGRADE_CATALOG_SOURCE_IMAGE")
	startingCSV := os.Getenv("STARTING_CSV")

	if upgradeCatalogImage == "" || startingCSV == "" {
		t.Skip("Skipping upgrade test: UPGRADE_CATALOG_SOURCE_IMAGE and STARTING_CSV must be set")
	}

	f := framework.Global

	log.Printf("Running operator upgrade test from %s to catalog image %s", startingCSV, upgradeCatalogImage)

	// PRE-UPGRADE CHECKS
	log.Print("PRE-UPGRADE: Checking MachineConfigPool status")
	if err := f.WaitForMachineConfigPoolToBeHealthy("master", 15*time.Minute); err != nil {
		t.Fatalf("Master MachineConfigPool is not healthy before upgrade: %v", err)
	}
	if err := f.WaitForMachineConfigPoolToBeHealthy("worker", 15*time.Minute); err != nil {
		t.Fatalf("Worker MachineConfigPool is not healthy before upgrade: %v", err)
	}

	log.Print("PRE-UPGRADE: Capturing resource snapshot")
	beforeSnapshot, err := f.GetResourceSnapshot(f.OperatorNamespace)
	if err != nil {
		t.Fatalf("Failed to get resource snapshot before upgrade: %v", err)
	}

	// Sanity check - ensure we have resources to track
	if len(beforeSnapshot.RuleNames) == 0 {
		t.Fatal("Expected to find rules before upgrade, but found none")
	}
	if len(beforeSnapshot.ProfileNames) == 0 {
		t.Fatal("Expected to find profiles before upgrade, but found none")
	}

	log.Printf("Resource snapshot before upgrade - Rules: %d, Variables: %d, Profiles: %d",
		len(beforeSnapshot.RuleNames), len(beforeSnapshot.VariableNames), len(beforeSnapshot.ProfileNames))

	// PERFORM UPGRADE
	log.Print("UPGRADE: Setting up upgrade catalog source")

	// Create CatalogSource if it doesn't exist
	catalogSourceName := "compliance-operator-upgrade"
	catalogSourceNS := "openshift-marketplace"

	catalogSource := &apiv1alpha1.CatalogSource{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{
		Name:      catalogSourceName,
		Namespace: catalogSourceNS,
	}, catalogSource)

	if apierrors.IsNotFound(err) {
		// CatalogSource doesn't exist, create it
		log.Printf("Creating CatalogSource %s from image: %s", catalogSourceName, upgradeCatalogImage)

		catalogSource = &apiv1alpha1.CatalogSource{
			ObjectMeta: metav1.ObjectMeta{
				Name:      catalogSourceName,
				Namespace: catalogSourceNS,
			},
			Spec: apiv1alpha1.CatalogSourceSpec{
				SourceType:  apiv1alpha1.SourceTypeGrpc,
				Image:       upgradeCatalogImage,
				DisplayName: "Compliance Operator Upgrade Test",
				Publisher:   "OpenShift QE",
				UpdateStrategy: &apiv1alpha1.UpdateStrategy{
					RegistryPoll: &apiv1alpha1.RegistryPoll{
						Interval: &metav1.Duration{Duration: 15 * time.Minute},
					},
				},
			},
		}

		err = f.Client.Create(context.TODO(), catalogSource, nil)
		if err != nil {
			t.Fatalf("Failed to create CatalogSource: %v", err)
		}
		log.Printf("CatalogSource %s created", catalogSourceName)

		// Clean up CatalogSource after test
		defer func() {
			log.Printf("Cleaning up CatalogSource %s", catalogSourceName)
			f.Client.Delete(context.TODO(), catalogSource)
		}()

		// Wait for CatalogSource to be READY
		log.Print("Waiting for CatalogSource to become READY...")
		err = wait.Poll(10*time.Second, 5*time.Minute, func() (bool, error) {
			cs := &apiv1alpha1.CatalogSource{}
			err := f.Client.Get(context.TODO(), types.NamespacedName{
				Name:      catalogSourceName,
				Namespace: catalogSourceNS,
			}, cs)
			if err != nil {
				return false, err
			}

			if cs.Status.GRPCConnectionState != nil &&
				cs.Status.GRPCConnectionState.LastObservedState == "READY" {
				log.Printf("CatalogSource is READY")
				return true, nil
			}
			return false, nil
		})
		if err != nil {
			t.Fatalf("Timeout waiting for CatalogSource to be READY: %v", err)
		}
	} else if err != nil {
		t.Fatalf("Failed to check if CatalogSource exists: %v", err)
	} else {
		log.Printf("CatalogSource %s already exists", catalogSourceName)
	}

	// Now perform the upgrade
	log.Print("UPGRADE: Patching subscription to trigger upgrade")

	// Get current CSV name for comparison
	currentCSV := &corev1.ObjectReference{}
	sub := &apiv1alpha1.Subscription{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{
		Name:      "compliance-operator",
		Namespace: f.OperatorNamespace,
	}, sub)
	if err != nil {
		t.Fatalf("Failed to get subscription: %v", err)
	}

	if sub.Status.InstalledCSV != "" {
		currentCSV.Name = sub.Status.InstalledCSV
		log.Printf("Current CSV: %s", currentCSV.Name)
	} else {
		t.Fatal("No installed CSV found in subscription status")
	}

	// Patch subscription to use upgrade catalog source
	// This assumes a CatalogSource named "compliance-operator-upgrade" exists
	log.Print("Patching subscription to use upgrade catalog source...")
	subPatch := []byte(`{
		"spec": {
			"source": "compliance-operator-upgrade",
			"installPlanApproval": "Automatic"
		}
	}`)

	err = f.Client.Patch(context.TODO(), sub, client.RawPatch(types.MergePatchType, subPatch))
	if err != nil {
		t.Fatalf("Failed to patch subscription: %v", err)
	}

	log.Print("Waiting for new InstallPlan to be created...")
	time.Sleep(10 * time.Second) // Give OLM time to create new InstallPlan

	// Find and approve the new InstallPlan
	var newInstallPlan *apiv1alpha1.InstallPlan
	err = wait.Poll(5*time.Second, 2*time.Minute, func() (bool, error) {
		ipList := &apiv1alpha1.InstallPlanList{}
		listOpts := &client.ListOptions{Namespace: f.OperatorNamespace}
		err := f.Client.List(context.TODO(), ipList, listOpts)
		if err != nil {
			return false, err
		}

		for i := range ipList.Items {
			ip := &ipList.Items[i]
			// Find InstallPlan that's for a different CSV than current
			if len(ip.Spec.ClusterServiceVersionNames) > 0 {
				csvName := ip.Spec.ClusterServiceVersionNames[0]
				if csvName != currentCSV.Name && !ip.Spec.Approved {
					newInstallPlan = ip
					log.Printf("Found new InstallPlan: %s for CSV: %s", ip.Name, csvName)
					return true, nil
				}
			}
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("Failed to find new InstallPlan: %v", err)
	}

	// Approve the InstallPlan
	log.Printf("Approving InstallPlan: %s", newInstallPlan.Name)
	newInstallPlan.Spec.Approved = true
	err = f.Client.Update(context.TODO(), newInstallPlan)
	if err != nil {
		t.Fatalf("Failed to approve InstallPlan: %v", err)
	}

	// Wait for new CSV to be installed
	log.Print("Waiting for new CSV to reach Succeeded phase...")
	err = wait.Poll(10*time.Second, 10*time.Minute, func() (bool, error) {
		csvList := &apiv1alpha1.ClusterServiceVersionList{}
		listOpts := &client.ListOptions{Namespace: f.OperatorNamespace}
		err := f.Client.List(context.TODO(), csvList, listOpts)
		if err != nil {
			return false, err
		}

		for i := range csvList.Items {
			csv := &csvList.Items[i]
			if csv.Name != currentCSV.Name && csv.Status.Phase == apiv1alpha1.CSVPhaseSucceeded {
				log.Printf("New CSV %s reached Succeeded phase", csv.Name)
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("Timeout waiting for new CSV to be installed: %v", err)
	}

	log.Print("Operator upgrade completed successfully!")

	// POST-UPGRADE CHECKS
	log.Print("POST-UPGRADE: Checking MachineConfigPool status")
	if err := f.WaitForMachineConfigPoolToBeHealthy("master", 15*time.Minute); err != nil {
		t.Fatalf("Master MachineConfigPool is not healthy after upgrade: %v", err)
	}
	if err := f.WaitForMachineConfigPoolToBeHealthy("worker", 15*time.Minute); err != nil {
		t.Fatalf("Worker MachineConfigPool is not healthy after upgrade: %v", err)
	}

	log.Print("POST-UPGRADE: Capturing resource snapshot")
	afterSnapshot, err := f.GetResourceSnapshot(f.OperatorNamespace)
	if err != nil {
		t.Fatalf("Failed to get resource snapshot after upgrade: %v", err)
	}

	log.Printf("Resource snapshot after upgrade - Rules: %d, Variables: %d, Profiles: %d",
		len(afterSnapshot.RuleNames), len(afterSnapshot.VariableNames), len(afterSnapshot.ProfileNames))

	// VALIDATE: Resources should not be lost during upgrade
	log.Print("VALIDATION: Comparing resource snapshots")
	diff, err := f.CompareResourceSnapshots(beforeSnapshot, afterSnapshot, "after upgrade")
	if err != nil {
		// When upgrade causes resource loss, show exactly what was removed
		t.Fatalf("UPGRADE VALIDATION FAILED - Resources were lost:\n%v\n\nDetailed diff:\n%s",
			err, diff.String())
	}

	// Log any changes (additions are expected in upgrades, removals are failures)
	if diff.HasChanges() {
		log.Printf("Resource changes during upgrade:\n%s", diff.String())
		if len(diff.AddedRules) > 0 || len(diff.AddedVariables) > 0 || len(diff.AddedProfiles) > 0 {
			log.Print("New resources were added during upgrade (this is expected)")
		}
	} else {
		log.Print("No resource changes during upgrade")
	}

	log.Print("=== SUCCESS ===")
	log.Print("Operator upgrade validation passed:")
	log.Print("MachineConfigPools remained healthy")
	log.Print("No resources were lost")
	log.Print("Resource tracking functions work correctly")
>>>>>>> 49d3cdedd (moved upgrade test to a seperate suite)
}
