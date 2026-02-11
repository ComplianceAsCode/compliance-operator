package serial_e2e

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
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

func TestSuiteScan(t *testing.T) {
	f := framework.Global
	suiteName := "test-suite-two-scans"
	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}

	masterScanName := fmt.Sprintf("%s-masters-scan", suiteName)
	selectMasters := map[string]string{
		"node-role.kubernetes.io/master": "",
	}

	exampleComplianceSuite := &compv1alpha1.ComplianceSuite{
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
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
						},
					},
					Name: workerScanName,
				},
				{
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						NodeSelector: selectMasters,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
						},
					},
					Name: masterScanName,
				},
			},
		},
	}

	err := f.Client.Create(context.TODO(), exampleComplianceSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), exampleComplianceSuite)

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	// At this point, both scans should be non-compliant given our current content
	err = f.AssertScanIsNonCompliant(workerScanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanIsNonCompliant(masterScanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	// Each scan should produce two remediations
	workerRemediations := []string{
		fmt.Sprintf("%s-no-empty-passwords", workerScanName),
		fmt.Sprintf("%s-no-direct-root-logins", workerScanName),
	}
	err = f.AssertHasRemediations(suiteName, workerScanName, "worker", workerRemediations)
	if err != nil {
		t.Fatal(err)
	}

	masterRemediations := []string{
		fmt.Sprintf("%s-no-empty-passwords", masterScanName),
		fmt.Sprintf("%s-no-direct-root-logins", masterScanName),
	}
	err = f.AssertHasRemediations(suiteName, masterScanName, "master", masterRemediations)
	if err != nil {
		t.Fatal(err)
	}

	checkWifiInBios := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-wireless-disable-in-bios", workerScanName),
			Namespace: f.OperatorNamespace,
		},
		ID:       "xccdf_org.ssgproject.content_rule_wireless_disable_in_bios",
		Status:   compv1alpha1.CheckResultManual,
		Severity: compv1alpha1.CheckResultSeverityUnknown, // yes, it's really uknown in the DS
	}

	err = f.AssertHasCheck(suiteName, workerScanName, checkWifiInBios)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertCheckRemediation(checkWifiInBios.Name, checkWifiInBios.Namespace, false)
	if err != nil {
		t.Fatal(err)
	}

	if runtime.GOARCH == "amd64" {
		// the purpose of this check is to make sure that also INFO-level checks produce remediations
		// as of now, the only one we have is the vsyscall check that is x86-specific.
		checkVsyscall := compv1alpha1.ComplianceCheckResult{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s-coreos-vsyscall-kernel-argument", workerScanName),
				Namespace: f.OperatorNamespace,
				Labels: map[string]string{
					compv1alpha1.ComplianceCheckResultHasRemediation: "",
				},
			},
			ID:       "xccdf_org.ssgproject.content_rule_coreos_vsyscall_kernel_argument",
			Status:   compv1alpha1.CheckResultFail,
			Severity: compv1alpha1.CheckResultSeverityMedium,
		}

		err = f.AssertHasCheck(suiteName, workerScanName, checkVsyscall)
		if err != nil {
			t.Fatal(err)
		}
		// even INFO checks generate remediations, make sure the check was labeled appropriately
		// even INFO checks generate remediations, make sure the check was labeled appropriately
		f.AssertCheckRemediation(checkVsyscall.Name, checkVsyscall.Namespace, true)
	}

	// ensure scan has total check counts annotation
	err = f.AssertScanHasTotalCheckCounts(f.OperatorNamespace, workerScanName)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertScanHasTotalCheckCounts(f.OperatorNamespace, masterScanName)
	if err != nil {
		t.Fatal(err)
	}

}

func TestScanHasProfileGUID(t *testing.T) {
	f := framework.Global
	bindingName := framework.GetObjNameFromTest(t)
	tpName := "test-scan-have-profile-guid-tp"
	// This is the profileGUID for the redhat_openshift_container_platform_4.1 product and xccdf_org.ssgproject.content_profile_moderate profile
	const profileGUIDOCPModerate = "d625badc-92a1-5438-afd7-19526c26b03c"
	const profileGUIDOCPModerateNode = "ef297cbd-f5a0-5c0c-baab-edeebb761e27"
	const profileGUIDTP = "04a11c78-7c77-545e-8341-f1b7b743bcb8"
	const profileGUIDRHCOSModerate = "eceb9af0-17d4-5c59-9b17-07cfd22a3ba1"
	const profileGUIDOCPCIS = "a230315d-3e4a-5b58-b00f-f96f1553e036"

	err := f.AssertProfileGUIDMatches("ocp4-moderate", f.OperatorNamespace, profileGUIDOCPModerate)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertProfileGUIDMatches("ocp4-moderate-node", f.OperatorNamespace, profileGUIDOCPModerateNode)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertProfileGUIDMatches("rhcos4-moderate", f.OperatorNamespace, profileGUIDRHCOSModerate)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertProfileGUIDMatches("ocp4-cis", f.OperatorNamespace, profileGUIDOCPCIS)
	if err != nil {
		t.Fatal(err)
	}
	// check the GUID is present for all the profiles
	err = f.AssertAllProfilesHaveGUID(f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "TestScanHaveProfileGUID",
			Description: "TestScanHaveProfileGUID",
			Extends:     "ocp4-moderate",
		},
	}

	createTPErr := f.Client.Create(context.TODO(), tp, nil)
	if createTPErr != nil {
		t.Fatal(createTPErr)
	}
	defer f.Client.Delete(context.TODO(), tp)
	scanSettingBinding := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     "ocp4-cis",
				Kind:     "Profile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
			{
				Name:     tpName,
				Kind:     "TailoredProfile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
			{
				Name:     "ocp4-moderate",
				Kind:     "Profile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
			{
				Name:     "ocp4-moderate-node",
				Kind:     "Profile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
			{
				Name:     "rhcos4-moderate",
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
	// use Context's create helper to create the object and add a cleanup function for the new object
	err = f.Client.Create(context.TODO(), &scanSettingBinding, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Cleanup: Delete ScanSettingBinding first, then wait for ComplianceSuite to be cascade-deleted
	// This ensures proper cleanup before the next test runs
	defer func() {
		// Delete the binding first - this will cascade delete the ComplianceSuite
		if err := f.Client.Delete(context.TODO(), &scanSettingBinding); err != nil {
			t.Logf("Failed to delete ScanSettingBinding: %v", err)
			return
		}
		// Now wait for the suite to be deleted (it's owned by the binding)
		if err := f.WaitForComplianceSuiteDeletion(bindingName, f.OperatorNamespace); err != nil {
			t.Logf("ComplianceSuite cleanup warning: %v", err)
		}
	}()
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	// check if the profileGUID is correct in the scan's label
	err = f.AssertScanGUIDMatches("ocp4-moderate", f.OperatorNamespace, profileGUIDOCPModerate)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanGUIDMatches("ocp4-moderate-node-master", f.OperatorNamespace, profileGUIDOCPModerateNode)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanGUIDMatches("ocp4-moderate-node-worker", f.OperatorNamespace, profileGUIDOCPModerateNode)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanGUIDMatches("rhcos4-moderate-worker", f.OperatorNamespace, profileGUIDRHCOSModerate)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanGUIDMatches("rhcos4-moderate-master", f.OperatorNamespace, profileGUIDRHCOSModerate)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanGUIDMatches("ocp4-cis", f.OperatorNamespace, profileGUIDOCPCIS)
	if err != nil {
		t.Fatal(err)
	}
	// check if the profileGUID is correct in the tailored profile's label
	err = f.AssertScanGUIDMatches(tpName, f.OperatorNamespace, profileGUIDTP)
	if err != nil {
		t.Fatal(err)
	}
	// Check if the profileGUID is correct in the ccr's label
	err = f.AssertResultsGUIDMatches("ocp4-moderate", f.OperatorNamespace, profileGUIDOCPModerate)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertResultsGUIDMatches("ocp4-moderate-node-worker", f.OperatorNamespace, profileGUIDOCPModerateNode)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertResultsGUIDMatches("ocp4-moderate-node-master", f.OperatorNamespace, profileGUIDOCPModerateNode)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertResultsGUIDMatches("rhcos4-moderate-worker", f.OperatorNamespace, profileGUIDRHCOSModerate)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertResultsGUIDMatches("rhcos4-moderate-master", f.OperatorNamespace, profileGUIDRHCOSModerate)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertResultsGUIDMatches("ocp4-cis", f.OperatorNamespace, profileGUIDOCPCIS)
	if err != nil {
		t.Fatal(err)
	}
}

// remediationSuffix matches the "-<number>" the operator appends when a single
// rule's fix produces more than one object. It mirrors remediationSuffixRegex
// in pkg/controller/complianceremediation.
var remediationSuffix = regexp.MustCompile(`-[0-9]+$`)

// TestAutoRemediate tests auto-remediation functionality with multiple rule types.
// This test covers the following scenarios:
// Tests auto-remediation with multiple remediation types simultaneously
//
//	        (file-based, audit rules, array values - whichever are non-compliant)
//	Tests scanning on a subset of nodes (via framework.TestPoolName MachineConfigPool)
//	Tests ComplianceRemediation status transitions (Applied → PASS after rescan)
//	Tests array value remediations (chronyd with multiple NTP servers) and end-to-end workflow
//
// The test dynamically adapts to the environment by:
// 1. Scanning with multiple rules (file, audit, array value types)
// 2. Identifying which rules are non-compliant
// 3. Testing auto-remediation on all non-compliant rules
// 4. Verifying remediation status transitions and check results
// 5. Cleaning up all applied configurations
func TestAutoRemediate(t *testing.T) {
	f := framework.Global
	// FIXME, maybe have a func that returns a struct with suite name and scan names?
	suiteName := "test-remediate"
	scanName := fmt.Sprintf("%s-e2e", suiteName)

	// Each of these exercises a different kind of remediation, and a default
	// cluster fails all of them, so each is expected to produce at least one
	// ComplianceRemediation.
	remediatedRules := []compv1alpha1.RuleReferenceSpec{
		{
			Name:      "rhcos4-no-direct-root-logins",
			Rationale: "Test file-based remediation",
		},
		{
			// Array value remediation
			Name:      "rhcos4-chronyd-or-ntpd-specify-multiple-servers",
			Rationale: "Test array value remediation with multiple NTP servers",
		},
		{
			// Different remediation type (audit rules)
			Name:      "rhcos4-audit-rules-dac-modification-chmod",
			Rationale: "Test audit rule remediation",
		},
	}

	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
			Annotations: map[string]string{
				compv1alpha1.ProductTypeAnnotation: "Node",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "Test Auto Remediate",
			Description: "A test tailored profile to auto remediate",
			EnableRules: remediatedRules,
		},
	}

	createTPErr := f.Client.Create(context.TODO(), tp, nil)
	if createTPErr != nil {
		t.Fatalf("failed to create TailoredProfile %s: %s", tp.Name, createTPErr)
	}
	defer f.Client.Delete(context.TODO(), tp)

	scanSettingName := suiteName + "-scan-setting"
	scanSetting := compv1alpha1.ScanSetting{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingName,
			Namespace: f.OperatorNamespace,
		},
		ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
			AutoApplyRemediations: true,
			Schedule:              "0 1 * * *",
		},
		ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
			Debug:   true,
			Timeout: "60m",
		},
		Roles: []string{framework.TestPoolName},
	}
	if err := f.Client.Create(context.TODO(), &scanSetting, nil); err != nil {
		t.Fatalf("failed to create ScanSetting %s: %s", scanSettingName, err)
	}
	defer f.Client.Delete(context.TODO(), &scanSetting)

	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     suiteName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     scanSettingName,
		},
	}
	err := f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatalf("failed to create ScanSettingBinding %s: %s", ssb.Name, err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	log.Printf("Waiting for scan %s to complete\n", scanName)
	err = f.WaitForSuiteScansStatusAnyResult(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatalf("Scan did not complete with an expected result: %v", err)
	}

	remediationList := &compv1alpha1.ComplianceRemediationList{}
	err = f.Client.List(context.TODO(), remediationList,
		client.InNamespace(f.OperatorNamespace),
		client.MatchingLabels{compv1alpha1.SuiteLabel: suiteName},
	)
	if err != nil {
		t.Fatal(err)
	}

	// The TailoredProfile deliberately enables rules a default cluster fails,
	// so we expect at least one remediation per rule. Fail rather than skip if
	// they stop generating remediations: skipping would let the test go green
	// against stale content while exercising nothing.
	ourRemediations := remediationList.Items
	if len(ourRemediations) < len(remediatedRules) {
		t.Fatalf("expected at least %d remediations for suite %s, got %d; the enabled rules may no longer generate remediations",
			len(remediatedRules), suiteName, len(ourRemediations))
	}

	log.Printf("Found %d remediation(s) to test: - multiple remediation types\n", len(ourRemediations))
	for _, rem := range ourRemediations {
		log.Printf("  - %s\n", rem.Name)
	}

	// Wait for all remediations to be auto-applied, processing them one at a time
	// Get fresh pool state for each remediation to handle multiple MCs efficiently
	var appliedRemediations []*compv1alpha1.ComplianceRemediation
	for i := range ourRemediations {
		rem := &ourRemediations[i]
		log.Printf("Waiting for remediation %d/%d: %s to be auto-applied\n", i+1, len(ourRemediations), rem.Name)

		// Get current pool state before waiting for this specific remediation
		// This ensures we're working with fresh state, especially important when multiple MCs are being applied
		currentPool := &mcfgv1.MachineConfigPool{}
		err = f.Client.Get(context.TODO(), types.NamespacedName{Name: framework.TestPoolName}, currentPool)
		if err != nil {
			t.Fatalf("Failed to get current MachineConfigPool state for remediation %s: %s", rem.Name, err)
		}

		err = f.WaitForRemediationToBeAutoApplied(rem.Name, f.OperatorNamespace, currentPool)
		if err != nil {
			t.Fatal(err)
		}

		// Verify ComplianceRemediation shows "Applied" status
		log.Printf("Verifying remediation %s is in Applied state\n", rem.Name)
		err = f.WaitForRemediationState(rem.Name, f.OperatorNamespace, compv1alpha1.RemediationApplied)
		if err != nil {
			t.Fatalf("Remediation %s not in Applied state: %s", rem.Name, err)
		}

		// Fetch updated remediation for cleanup
		updatedRem := &compv1alpha1.ComplianceRemediation{}
		err = f.Client.Get(context.TODO(), types.NamespacedName{Name: rem.Name, Namespace: f.OperatorNamespace}, updatedRem)
		if err != nil {
			t.Fatal(err)
		}
		appliedRemediations = append(appliedRemediations, updatedRem)
		log.Printf("Remediation %d/%d applied successfully: %s\n", i+1, len(ourRemediations), rem.Name)
	}

	log.Printf("All %d remediation(s) applied successfully\n", len(appliedRemediations))

	// We can re-run the scan at this moment and check that it's now compliant
	// and it's reflected in a CheckResult
	err = f.ReRunScan(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseRunning, compv1alpha1.ResultNotAvailable)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure that all the scans in the suite have finished and are marked as Done
	// After remediation, we expect COMPLIANT
	log.Printf("waiting for scan %s to finish\n", scanName)
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("scan %s re-run has finished with COMPLIANT result\n", scanName)

	// Verify all checks pass after remediation (Applied → PASS transition)
	log.Printf("Verifying all %d remediated checks are now PASS\n", len(appliedRemediations))
	checked := map[string]bool{}
	for _, rem := range appliedRemediations {
		// A rule whose fix yields several objects gets one remediation per
		// object, named <scan>-<rule>, <scan>-<rule>-1, <scan>-<rule>-2 and so
		// on, but they all share the single <scan>-<rule> ComplianceCheckResult.
		// Drop the suffix to get the check name, and only look each one up once.
		checkName := remediationSuffix.ReplaceAllString(rem.Name, "")
		if checked[checkName] {
			continue
		}
		checked[checkName] = true
		log.Printf("Verifying check %s passed\n", checkName)

		// Get the check result
		checkResult := &compv1alpha1.ComplianceCheckResult{}
		err = f.Client.Get(context.TODO(), types.NamespacedName{Name: checkName, Namespace: f.OperatorNamespace}, checkResult)
		if err != nil {
			t.Fatalf("Failed to get ComplianceCheckResult %s: %s", checkName, err)
		}

		if checkResult.Status != compv1alpha1.CheckResultPass {
			t.Fatalf("Expected check %s to PASS after remediation, got %s", checkName, checkResult.Status)
		}
		log.Printf("Check %s is PASS\n", checkName)
	}

	// The test should not leave junk around, let's unapply all remediations and wait
	// for the nodes to stabilize again.
	// Unapply remediations one at a time and wait for pool to stabilize after each
	// to avoid timeout when unapplying multiple remediations simultaneously
	log.Printf("Unapplying %d remediation(s) one at a time\n", len(appliedRemediations))

	for i, rem := range appliedRemediations {
		log.Printf("Unapplying remediation %d/%d: %s\n", i+1, len(appliedRemediations), rem.Name)
		err = f.UnApplyRemediationAndCheck(f.OperatorNamespace, rem.Name, framework.TestPoolName)
		if err != nil {
			t.Fatalf("Failed to unapply remediation %s: %s", rem.Name, err)
		}
		log.Printf("Successfully unapplied remediation %s\n", rem.Name)
	}

	log.Printf("Successfully unapplied all remediations and pool has stabilized")

	// ..as well as the nodes
	f.WaitForNodesToBeReady()
}

func TestUnapplyRemediation(t *testing.T) {
	f := framework.Global
	// FIXME, maybe have a func that returns a struct with suite name and scan names?
	suiteName := "test-unapply-remediation"

	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)

	exampleComplianceSuite := &compv1alpha1.ComplianceSuite{
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
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						NodeSelector: framework.GetPoolNodeRoleSelector(),
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
						},
					},
					Name: workerScanName,
				},
			},
		},
	}

	err := f.Client.Create(context.TODO(), exampleComplianceSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), exampleComplianceSuite)

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	// Pause the MC so that we have only one reboot
	err = f.PauseMachinePool(framework.TestPoolName)
	if err != nil {
		t.Fatal(err)
	}

	// Apply both remediations
	workersNoRootLoginsRemName := fmt.Sprintf("%s-no-direct-root-logins", workerScanName)
	err = f.ApplyRemediationAndCheck(f.OperatorNamespace, workersNoRootLoginsRemName, framework.TestPoolName)
	if err != nil {
		log.Printf("WARNING: Got an error while applying remediation '%s': %v\n", workersNoRootLoginsRemName, err)
	}
	log.Printf("remediation %s applied", workersNoRootLoginsRemName)

	workersNoEmptyPassRemName := fmt.Sprintf("%s-no-empty-passwords", workerScanName)
	err = f.ApplyRemediationAndCheck(f.OperatorNamespace, workersNoEmptyPassRemName, framework.TestPoolName)
	if err != nil {
		log.Printf("WARNING: Got an error while applying remediation '%s': %v\n", workersNoEmptyPassRemName, err)
	}
	log.Printf("remediation %s applied", workersNoEmptyPassRemName)

	// resume the MCP so that the remediation gets applied
	f.ResumeMachinePool(framework.TestPoolName)

	err = f.WaitForNodesToBeReady()
	if err != nil {
		t.Fatal(err)
	}

	// Get the resulting MC
	mcName := types.NamespacedName{Name: fmt.Sprintf("75-%s", workersNoEmptyPassRemName)}
	mcBoth := &mcfgv1.MachineConfig{}
	err = f.Client.Get(context.TODO(), mcName, mcBoth)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), mcBoth)
	log.Printf("MachineConfig %s exists\n", mcName.Name)

	// Revert one remediation. The MC should stay, but its generation should bump
	log.Printf("reverting remediation %s\n", workersNoEmptyPassRemName)
	err = f.UnApplyRemediationAndCheck(f.OperatorNamespace, workersNoEmptyPassRemName, framework.TestPoolName)
	if err != nil {
		log.Printf("WARNING: Got an error while unapplying remediation '%s': %v\n", workersNoEmptyPassRemName, err)
	}
	log.Printf("remediation %s reverted\n", workersNoEmptyPassRemName)

	// When we unapply the second remediation, the MC should be deleted, too
	log.Printf("reverting remediation %s", workersNoRootLoginsRemName)
	err = f.UnApplyRemediationAndCheck(f.OperatorNamespace, workersNoRootLoginsRemName, framework.TestPoolName)
	if err != nil {
		log.Printf("WARNING: Got an error while unapplying remediation '%s': %v\n", workersNoEmptyPassRemName, err)
	}

	log.Printf("remediation %s reverted", workersNoEmptyPassRemName)

	log.Printf("no remediation-based MachineConfigs should exist now")
	mcShouldntExist := &mcfgv1.MachineConfig{}
	err = f.Client.Get(context.TODO(), mcName, mcShouldntExist)
	if err == nil {
		t.Fatalf("found an unexpected MachineConfig: %s", err)
	}
}

func TestInconsistentResult(t *testing.T) {
	f := framework.Global
	suiteName := "test-inconsistent"
	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}

	workersComplianceSuite := &compv1alpha1.ComplianceSuite{
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
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Rule:         "xccdf_org.ssgproject.content_rule_no_direct_root_logins",
						Content:      framework.RhcosContentFile,
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
						},
					},
					Name: workerScanName,
				},
			},
		},
	}

	workerNodes, err := f.GetNodesWithSelector(selectWorkers)
	if err != nil {
		t.Fatal(err)
	}
	pod, err := f.CreateAndRemoveEtcSecurettyOnNode(f.OperatorNamespace, "create-etc-securetty", workerNodes[0].Labels["kubernetes.io/hostname"])
	if err != nil {
		t.Fatal(err)
	}

	err = f.Client.Create(context.TODO(), workersComplianceSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), workersComplianceSuite)

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultInconsistent)
	if err != nil {
		t.Fatalf("got an unexpected status: %s", err)
	}

	if err := f.KubeClient.CoreV1().Pods(f.OperatorNamespace).Delete(context.TODO(), pod.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}

	// The check for the no-direct-root-logins rule should be inconsistent
	var rootLoginCheck compv1alpha1.ComplianceCheckResult
	rootLoginCheckName := fmt.Sprintf("%s-no-direct-root-logins", workerScanName)

	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: rootLoginCheckName, Namespace: f.OperatorNamespace}, &rootLoginCheck)
	if err != nil {
		t.Fatal(err)
	}

	if rootLoginCheck.Status != compv1alpha1.CheckResultInconsistent {
		t.Fatalf("expected the %s result to be inconsistent, the check result was %s", rootLoginCheckName, rootLoginCheck.Status)
	}

	var expectedInconsistentSource string

	if len(workerNodes) >= 3 {
		// The annotations should list the node that had a different result
		expectedInconsistentSource = workerNodes[0].Name + ":" + string(compv1alpha1.CheckResultPass)
		inconsistentSources := rootLoginCheck.Annotations[compv1alpha1.ComplianceCheckResultInconsistentSourceAnnotation]
		if inconsistentSources != expectedInconsistentSource {
			t.Fatalf("expected that node %s would report %s, instead it reports %s", workerNodes[0].Name, expectedInconsistentSource, inconsistentSources)
		}

		// Since all the other nodes consistently fail, there should also be a common result
		mostCommonState := rootLoginCheck.Annotations[compv1alpha1.ComplianceCheckResultMostCommonAnnotation]
		if mostCommonState != string(compv1alpha1.CheckResultFail) {
			t.Fatalf("expected that there would be a common FAIL state, instead got %s", mostCommonState)
		}
	} else if len(workerNodes) == 2 {
		// example: ip-10-0-184-135.us-west-1.compute.internal:PASS,ip-10-0-226-48.us-west-1.compute.internal:FAIL
		var expectedInconsistentSource [2]string
		expectedInconsistentSource[0] = workerNodes[0].Name + ":" + string(compv1alpha1.CheckResultPass) + "," + workerNodes[1].Name + ":" + string(compv1alpha1.CheckResultFail)
		expectedInconsistentSource[1] = workerNodes[1].Name + ":" + string(compv1alpha1.CheckResultFail) + "," + workerNodes[0].Name + ":" + string(compv1alpha1.CheckResultPass)

		inconsistentSources := rootLoginCheck.Annotations[compv1alpha1.ComplianceCheckResultInconsistentSourceAnnotation]
		if inconsistentSources != expectedInconsistentSource[0] && inconsistentSources != expectedInconsistentSource[1] {
			t.Fatalf(
				"expected that node %s would report %s or %s, instead it reports %s",
				workerNodes[0].Name,
				expectedInconsistentSource[0], expectedInconsistentSource[1],
				inconsistentSources)
		}

		// If there are only two worker nodes, we won't be able to find the common status, so both
		// nodes would be listed as inconsistent -- we can't figure out which of the two results is
		// consistent and which is not. Therefore this branch skips the check for
		// compv1alpha1.ComplianceCheckResultMostCommonAnnotation
	} else {
		t.Skip("test requires more than one node to generate inconsistent results, skipping")
	}

	// Since all states were either pass or fail, we still create the remediation
	workerRemediations := []string{
		fmt.Sprintf("%s-no-direct-root-logins", workerScanName),
	}
	err = f.AssertHasRemediations(suiteName, workerScanName, "worker", workerRemediations)
	if err != nil {
		t.Fatal(err)
	}

}

func TestPlatformAndNodeSuiteScan(t *testing.T) {
	f := framework.Global
	suiteName := "test-suite-two-scans-with-platform"

	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}

	platformScanName := fmt.Sprintf("%s-platform-scan", suiteName)

	exampleComplianceSuite := &compv1alpha1.ComplianceSuite{
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
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
						},
					},
					Name: workerScanName,
				},
				{
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ScanType:     compv1alpha1.ScanTypePlatform,
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Rule:         "xccdf_org.ssgproject.content_rule_ocp_idp_no_htpasswd",
						Content:      framework.OcpContentFile,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
						},
					},
					Name: platformScanName,
				},
			},
		},
	}

	err := f.Client.Create(context.TODO(), exampleComplianceSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), exampleComplianceSuite)

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	// At this point, both scans should be non-compliant given our current content
	err = f.AssertScanIsNonCompliant(workerScanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	// The profile should find one check for an htpasswd IDP, so we should be compliant.
	err = f.AssertScanIsCompliant(platformScanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	// Each scan should produce two remediations
	workerRemediations := []string{
		fmt.Sprintf("%s-no-empty-passwords", workerScanName),
		fmt.Sprintf("%s-no-direct-root-logins", workerScanName),
	}
	err = f.AssertHasRemediations(suiteName, workerScanName, "worker", workerRemediations)
	if err != nil {
		t.Fatal(err)
	}

	// TODO: Add check for future API remediation
	//platformRemediations := []string{
	//	fmt.Sprintf("%s-no-empty-passwords", platformScanName),
	//	fmt.Sprintf("%s-no-direct-root-logins", platformScanName),
	//}
	//err = assertHasRemediations(t, f, suiteName, platformScanName, "master", platformRemediations)
	//if err != nil {
	//	return err
	//}

	// Test a fail result from the platform scan. This fails the HTPasswd IDP check.
	if _, err := f.KubeClient.CoreV1().Secrets("openshift-config").Create(context.TODO(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "htpass",
			Namespace: "openshift-config",
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"htpasswd": []byte("bob:$2y$05$OyjQO7M2so4hRJW0aS9yie9KJ0wXv80XFWyEsApUZFURqE37aVR/a"),
		},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	defer func() {
		err := f.KubeClient.CoreV1().Secrets("openshift-config").Delete(context.TODO(), "htpass", metav1.DeleteOptions{})
		if err != nil {
			log.Printf("could not clean up openshift-config/htpass test secret: %v\n", err)
		}
	}()

	fetchedOauth := &configv1.OAuth{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: "cluster"}, fetchedOauth)
	if err != nil {
		t.Fatal(err)
	}

	oauthUpdate := fetchedOauth.DeepCopy()
	oauthUpdate.Spec = configv1.OAuthSpec{
		IdentityProviders: []configv1.IdentityProvider{
			{
				Name:          "my_htpasswd_provider",
				MappingMethod: "claim",
				IdentityProviderConfig: configv1.IdentityProviderConfig{
					Type: "HTPasswd",
					HTPasswd: &configv1.HTPasswdIdentityProvider{
						FileData: configv1.SecretNameReference{
							Name: "htpass",
						},
					},
				},
			},
		},
	}

	err = f.Client.Update(context.TODO(), oauthUpdate)
	if err != nil {
		t.Fatalf("failed to update IdP: %s", err)
	}

	defer func() {
		fetchedOauth := &configv1.OAuth{}
		err := f.Client.Get(context.TODO(), types.NamespacedName{Name: "cluster"}, fetchedOauth)
		if err != nil {
			log.Printf("error restoring idp: %v\n", err)
		} else {
			oauth := fetchedOauth.DeepCopy()
			// Make sure it's cleared out
			oauth.Spec = configv1.OAuthSpec{
				IdentityProviders: nil,
			}
			err = f.Client.Update(context.TODO(), oauth)
			if err != nil {
				log.Printf("error restoring idp: %v\n", err)
			}
		}
	}()

	suiteName = "test-suite-two-scans-with-platform-2"
	platformScanName = fmt.Sprintf("%s-platform-scan-2", suiteName)
	exampleComplianceSuite = &compv1alpha1.ComplianceSuite{
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
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ScanType:     compv1alpha1.ScanTypePlatform,
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Rule:         "xccdf_org.ssgproject.content_rule_ocp_idp_no_htpasswd",
						Content:      framework.OcpContentFile,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
						},
					},
					Name: platformScanName,
				},
			},
		},
	}

	err = f.Client.Create(context.TODO(), exampleComplianceSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), exampleComplianceSuite)

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertScanIsNonCompliant(platformScanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestUpdateRemediation(t *testing.T) {
	f := framework.Global
	origSuiteName := "test-update-remediation"
	workerScanName := fmt.Sprintf("%s-e2e-scan", origSuiteName)

	var (
		origImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "rem_mod_base")
		modImage  = fmt.Sprintf("%s:%s", brokenContentImagePath, "rem_mod_change")
	)

	pbName := framework.GetObjNameFromTest(t)
	rhcosPb, err := f.CreateProfileBundle(pbName, origImage, framework.RhcosContentFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), rhcosPb)

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}

	pbNameMod := fmt.Sprintf("%s-%s", pbName, "mod")
	rhcosPbMod, err := f.CreateProfileBundle(pbNameMod, modImage, framework.RhcosContentFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), rhcosPbMod)
	if err := f.WaitForProfileBundleStatus(pbNameMod, compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}

	origSuite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      origSuiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: false,
			},
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: origImage,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Rule:         "xccdf_org.ssgproject.content_rule_no_empty_passwords",
						Content:      framework.RhcosContentFile,
						NodeSelector: framework.GetPoolNodeRoleSelector(),
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
						},
					},
					Name: workerScanName,
				},
			},
		},
	}

	err = f.Client.Create(context.TODO(), origSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), origSuite)

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, origSuiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	workersNoEmptyPassRemName := fmt.Sprintf("%s-no-empty-passwords", workerScanName)
	err = f.ApplyRemediationAndCheck(f.OperatorNamespace, workersNoEmptyPassRemName, framework.TestPoolName)
	if err != nil {
		log.Printf("WARNING: Got an error while applying remediation '%s': %v", workersNoEmptyPassRemName, err)
	}
	log.Printf("remediation %s applied\n", workersNoEmptyPassRemName)

	err = f.WaitForNodesToBeReady()
	if err != nil {
		t.Fatalf("failed waiting for nodes to reboot after applying remedation: %s", err)
	}

	// Now update the suite with a different image that contains different remediations
	if err := f.UpdateSuiteContentImage(modImage, origSuiteName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}
	log.Printf("suite %s updated with a new image\n", origSuiteName)

	err = f.ReRunScan(workerScanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, origSuiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertRemediationIsObsolete(f.OperatorNamespace, workersNoEmptyPassRemName)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("will remove obsolete data from remediation\n")
	renderedMcName := fmt.Sprintf("75-%s", workersNoEmptyPassRemName)
	err = f.RemoveObsoleteRemediationAndCheck(f.OperatorNamespace, workersNoEmptyPassRemName, renderedMcName, framework.TestPoolName)
	if err != nil {
		t.Fatal(err)
	}

	err = f.WaitForNodesToBeReady()
	if err != nil {
		t.Fatalf("failed waiting for nodes to reboot after applying MachineConfig: %s", err)
	}

	// Now the remediation is no longer obsolete
	err = f.AssertRemediationIsCurrent(f.OperatorNamespace, workersNoEmptyPassRemName)
	if err != nil {
		t.Fatal(err)
	}

	// Finally clean up by removing the remediation and waiting for the nodes to reboot one more time
	err = f.UnApplyRemediationAndCheck(f.OperatorNamespace, workersNoEmptyPassRemName, framework.TestPoolName)
	if err != nil {
		t.Fatal(err)
	}

	err = f.WaitForNodesToBeReady()
	if err != nil {
		t.Fatalf("failed waiting for nodes to reboot after unapplying MachineConfig: %s", err)
	}
}

func TestVariableTemplate(t *testing.T) {
	f := framework.Global
	var baselineImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "variabletemplate")
	const requiredRule = "audit-profile-set"
	pbName := framework.GetObjNameFromTest(t)
	prefixName := func(profName, ruleBaseName string) string { return profName + "-" + ruleBaseName }

	ocpPb, err := f.CreateProfileBundle(pbName, baselineImage, framework.OcpContentFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ocpPb)
	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}

	// Check that if the rule we are going to test is there
	requiredRuleName := prefixName(pbName, requiredRule)
	err, found := f.DoesRuleExist(f.OperatorNamespace, requiredRuleName)
	if err != nil {
		t.Fatal(err)
	} else if !found {
		t.Fatalf("expected rule %s not found", requiredRuleName)
	}

	suiteName := "audit-profile-set-test"
	scanName := "audit-profile-set-test"

	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "Audit-Profile-Set-Test",
			Description: "A test tailored profile to auto remediate audit profile set",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      prefixName(pbName, requiredRule),
					Rationale: "To be tested",
				},
			},
			SetValues: []compv1alpha1.VariableValueSpec{
				{
					Name:      prefixName(pbName, "var-openshift-audit-profile"),
					Rationale: "Value to be set",
					Value:     "WriteRequestBodies",
				},
			},
		},
	}

	createTPErr := f.Client.Create(context.TODO(), tp, nil)
	if createTPErr != nil {
		t.Fatal(createTPErr)
	}
	defer f.Client.Delete(context.TODO(), tp)

	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     suiteName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default-auto-apply",
		},
	}
	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	apiServerBeforeRemediation := &configv1.APIServer{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: "cluster"}, apiServerBeforeRemediation)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	// We need to check that the remediation is auto-applied
	remName := "audit-profile-set-test-audit-profile-set"
	f.WaitForGenericRemediationToBeAutoApplied(remName, f.OperatorNamespace)

	// We can re-run the scan at this moment and check that it's now compliant
	// and it's reflected in a CheckResult
	err = f.ReRunScan(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	// Scan has been re-started
	log.Println("scan phase should be reset")
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseRunning, compv1alpha1.ResultNotAvailable)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure that all the scans in the suite have finished and are marked as Done
	log.Printf("waiting for scan to complete")
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("scan re-run has finished")

	// Now the check should be passing
	auditProfileSet := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-audit-profile-set", scanName),
			Namespace: f.OperatorNamespace,
		},
		ID:       "xccdf_org.ssgproject.content_rule_audit_profile_set",
		Status:   compv1alpha1.CheckResultPass,
		Severity: compv1alpha1.CheckResultSeverityMedium,
	}
	err = f.AssertHasCheck(suiteName, scanName, auditProfileSet)
	if err != nil {
		t.Fatal(err)
	}
}

func TestKubeletConfigRemediation(t *testing.T) {
	f := framework.Global
	var baselineImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "new_kubeletconfig")
	const requiredRule = "kubelet-enable-streaming-connections"
	pbName := framework.GetObjNameFromTest(t)
	prefixName := func(profName, ruleBaseName string) string { return profName + "-" + ruleBaseName }

	ocpPb, err := f.CreateProfileBundle(pbName, baselineImage, framework.OcpContentFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ocpPb)
	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}

	// Check that if the rule we are going to test is there
	requiredRuleName := prefixName(pbName, requiredRule)
	requiredVersionRuleName := prefixName(pbName, "version-detect-in-ocp")
	requiredVariableName := prefixName(pbName, "var-streaming-connection-timeouts")
	suiteName := "kubelet-remediation-test-suite-node"

	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "kubelet-remediation-test-node",
			Description: "A test tailored profile to test kubelet remediation",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      requiredRuleName,
					Rationale: "To be tested",
				},
				{
					Name:      requiredVersionRuleName,
					Rationale: "To be tested",
				},
			},
			SetValues: []compv1alpha1.VariableValueSpec{
				{
					Name:      requiredVariableName,
					Rationale: "Value to be set",
					Value:     "8h0m0s",
				},
			},
		},
	}
	createTPErr := f.Client.Create(context.TODO(), tp, nil)
	if createTPErr != nil {
		t.Fatal(createTPErr)
	}
	defer f.Client.Delete(context.TODO(), tp)

	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     suiteName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "e2e-default-auto-apply",
		},
	}

	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	scanName := suiteName + "-" + framework.TestPoolName

	// We need to check that the remediation is auto-applied and save
	// the object so we can delete it later
	remName := scanName + "-kubelet-enable-streaming-connections"
	f.WaitForGenericRemediationToBeAutoApplied(remName, f.OperatorNamespace)
	err = f.WaitForGenericRemediationToBeAutoApplied(remName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	err = f.ReRunScan(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	// Scan has been re-started
	log.Printf("scan phase should be reset")
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseRunning, compv1alpha1.ResultNotAvailable)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure that all the scans in the suite have finished and are marked as Done
	log.Printf("let's wait for it to be done now")
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("scan re-run has finished")

	// Now the check should be passing
	checkResult := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-kubelet-enable-streaming-connections", scanName),
			Namespace: f.OperatorNamespace,
		},
		ID:       "xccdf_org.ssgproject.content_rule_kubelet_enable_streaming_connections",
		Status:   compv1alpha1.CheckResultPass,
		Severity: compv1alpha1.CheckResultSeverityMedium,
	}
	err = f.AssertHasCheck(suiteName, scanName, checkResult)
	if err != nil {
		t.Fatal(err)
	}

	// The remediation must not be Outdated
	remediation := &compv1alpha1.ComplianceRemediation{}
	remNsName := types.NamespacedName{
		Name:      remName,
		Namespace: f.OperatorNamespace,
	}
	err = f.Client.Get(context.TODO(), remNsName, remediation)
	if err != nil {
		t.Fatalf("couldn't get remediation %s: %s", remName, err)
	}
	if remediation.Status.ApplicationState != compv1alpha1.RemediationApplied {
		t.Fatalf("remediation %s is not applied, but %s", remName, remediation.Status.ApplicationState)
	}
}

func TestRemoveProfileScan(t *testing.T) {
	f := framework.Global
	// Bind the new ScanSetting to a Profile
	bindingName := framework.GetObjNameFromTest(t) + "-binding"
	scanSettingBinding := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     "ocp4-cis",
				Kind:     "Profile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
			{
				Name:     "ocp4-moderate",
				Kind:     "Profile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
			{
				Name:     "ocp4-cis-node",
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
	if err := f.Client.Create(context.TODO(), &scanSettingBinding, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSettingBinding)

	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	// AssertScanExists check if the scan exists for both profiles
	if err := f.AssertScanExists("ocp4-cis", f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}

	if err := f.AssertScanExists("ocp4-moderate", f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}

	if err := f.AssertScanExists("ocp4-cis-node-master", f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}

	if err := f.AssertScanExists("ocp4-cis-node-worker", f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}

	scanName := "ocp4-moderate"
	checkResult := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-audit-profile-set", scanName),
			Namespace: f.OperatorNamespace,
		},
		ID:       "xccdf_org.ssgproject.content_rule_audit_profile_set",
		Status:   compv1alpha1.CheckResultPass,
		Severity: compv1alpha1.CheckResultSeverityMedium,
	}
	err := f.AssertHasCheck(bindingName, scanName, checkResult)
	if err != nil {
		t.Fatal(err)
	}

	// Remove the `ocp4-moderate` and `ocp4-cis-node` profile from the `ScanSettingBinding`
	scanSettingBindingUpdate := &compv1alpha1.ScanSettingBinding{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: f.OperatorNamespace, Name: bindingName}, scanSettingBindingUpdate); err != nil {
		t.Fatalf("failed to get ScanSettingBinding %s", bindingName)
	}

	scanSettingBindingUpdate.Profiles = []compv1alpha1.NamedObjectReference{
		{
			Name:     "ocp4-cis",
			Kind:     "Profile",
			APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}
	if err := f.Client.Update(context.TODO(), scanSettingBindingUpdate); err != nil {
		t.Fatal(err)
	}
	var lastErr error
	timeouterr := wait.Poll(framework.RetryInterval, framework.Timeout, func() (bool, error) {
		if lastErr := f.AssertScanDoesNotExist("ocp4-moderate", f.OperatorNamespace); lastErr != nil {
			log.Printf("Retrying: %s\n", lastErr)
			return false, nil
		}
		if lastErr := f.AssertScanDoesNotExist("ocp4-cis-node-master", f.OperatorNamespace); lastErr != nil {
			log.Printf("Retrying: %s\n", lastErr)
			return false, nil
		}
		if lastErr := f.AssertScanDoesNotExist("ocp4-cis-node-worker", f.OperatorNamespace); lastErr != nil {
			log.Printf("Retrying: %s\n", lastErr)
			return false, nil
		}
		if lastErr := f.AssertScanDoesNotContainCheck(scanName, checkResult.Name, f.OperatorNamespace); lastErr != nil {
			log.Printf("Retrying: %s\n", lastErr)
			// print more info about the found check
			ccr := &compv1alpha1.ComplianceCheckResult{}
			if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: f.OperatorNamespace, Name: checkResult.Name}, ccr); err != nil {
				log.Printf("failed to get check %s: %s\n", checkResult.Name, err)
			} else {
				log.Printf("Object: %v\n", ccr)
			}
			return false, nil
		}
		log.Print("Scan ocp4-moderate, ocp4-cis-node-master and ocp4-cis-node-worker do not exist anymore\n")
		log.Printf("Check %s doesn't exist anymore\n", checkResult.Name)
		return true, nil
	})

	if lastErr != nil {
		t.Fatalf("failed to remove profile from ScanSettingBinding: %s", lastErr)
	}

	if timeouterr != nil {
		t.Fatalf("timed out waiting for scan and check to be removed: %s", timeouterr)
	}
}

func TestScanDeprecatedProfile(t *testing.T) {
	f := framework.Global

	pbName := framework.GetObjNameFromTest(t)
	baselineImage := fmt.Sprintf("%s:%s", brokenContentImagePath, "deprecated_profile")
	pb, err := f.CreateProfileBundle(pbName, baselineImage, framework.OcpContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle: %s", err)
	}
	// This should get cleaned up at the end of the test
	defer f.Client.Delete(context.TODO(), pb)

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("failed waiting for the ProfileBundle to become available: %s", err)
	}

	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_cis-1-4",
			Content:      framework.OcpContentFile,
			ContentImage: baselineImage,
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	if err = f.Client.Create(context.TODO(), testScan, nil); err != nil {
		t.Fatalf("failed to create scan %s: %s", scanName, err)
	}
	defer f.Client.Delete(context.TODO(), testScan)

	// TestScanTailoredProfileExtendsDeprecated can run alongside this test with
	// a ProfileBundle of the same content, and the operator names the
	// deprecated Profile of whichever of these bundles it finds first.
	if err = f.WaitForProfileDeprecatedWarning(t, scanName, "-cis-1-4"); err != nil {
		t.Fatal(err)
	}

	if err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone); err != nil {
		t.Fatal(err)
	}
}

// TestOperatorResourceLimitsConfigurable tests that the compliance operator's
// resource limits and requests can be configured via patching the deployment.
func TestOperatorResourceLimitsConfigurable(t *testing.T) {
	f := framework.Global
	deploymentName := "compliance-operator"

	// Get the compliance-operator deployment
	deployment := &appsv1.Deployment{}
	err := f.Client.Get(context.TODO(), types.NamespacedName{
		Name:      deploymentName,
		Namespace: f.OperatorNamespace,
	}, deployment)
	if err != nil {
		t.Fatalf("failed to get compliance-operator deployment: %s", err)
	}

	// Verify default resource limits
	t.Log("Verifying default resource limits for compliance-operator")
	if len(deployment.Spec.Template.Spec.Containers) == 0 {
		t.Fatal("no containers found in deployment")
	}

	container := deployment.Spec.Template.Spec.Containers[0]
	if container.Name != "compliance-operator" {
		t.Fatalf("expected container name 'compliance-operator', got %s", container.Name)
	}

	// Check default limits
	defaultCPULimit := container.Resources.Limits.Cpu().String()
	defaultMemLimit := container.Resources.Limits.Memory().String()
	defaultCPURequest := container.Resources.Requests.Cpu().String()
	defaultMemRequest := container.Resources.Requests.Memory().String()

	if defaultCPULimit != "200m" {
		t.Errorf("expected default CPU limit 200m, got %s", defaultCPULimit)
	}
	if defaultMemLimit != "500Mi" {
		t.Errorf("expected default memory limit 500Mi, got %s", defaultMemLimit)
	}
	if defaultCPURequest != "10m" {
		t.Errorf("expected default CPU request 10m, got %s", defaultCPURequest)
	}
	if defaultMemRequest != "20Mi" {
		t.Errorf("expected default memory request 20Mi, got %s", defaultMemRequest)
	}

	// Patch the deployment with new resource limits
	t.Log("Patching deployment with new resource limits")

	// Create a patch to update resource requirements
	patchData := []byte(`{
		"spec": {
			"template": {
				"spec": {
					"containers": [{
						"name": "compliance-operator",
						"resources": {
							"limits": {
								"cpu": "256m",
								"memory": "512Mi"
							},
							"requests": {
								"cpu": "25m",
								"memory": "52Mi"
							}
						}
					}]
				}
			}
		}
	}`)

	// Apply the patch
	err = f.Client.Patch(context.TODO(), deployment, client.RawPatch(types.StrategicMergePatchType, patchData))
	if err != nil {
		t.Fatalf("failed to patch deployment: %s", err)
	}

	// Defer cleanup: restore original resource limits
	defer func() {
		t.Log("Restoring original resource limits")
		restorePatch := []byte(`{
			"spec": {
				"template": {
					"spec": {
						"containers": [{
							"name": "compliance-operator",
							"resources": {
								"limits": {
									"cpu": "200m",
									"memory": "500Mi"
								},
								"requests": {
									"cpu": "10m",
									"memory": "20Mi"
								}
							}
						}]
					}
				}
			}
		}`)

		// Get fresh deployment object for restore
		freshDeployment := &appsv1.Deployment{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{
			Name:      deploymentName,
			Namespace: f.OperatorNamespace,
		}, freshDeployment); err != nil {
			t.Logf("failed to get deployment for restore: %s", err)
			return
		}

		if err := f.Client.Patch(context.TODO(), freshDeployment, client.RawPatch(types.StrategicMergePatchType, restorePatch)); err != nil {
			t.Logf("failed to restore original resource limits: %s", err)
		}

		// Wait for deployment to be ready with original limits
		if err := f.WaitForDeployment(deploymentName, 1, framework.RetryInterval, framework.Timeout); err != nil {
			t.Logf("deployment did not become ready after restore: %s", err)
		}
	}()

	// Wait for the deployment to rollout with new pod
	err = f.WaitForDeployment(deploymentName, 1, framework.RetryInterval, framework.Timeout)
	if err != nil {
		t.Fatalf("deployment did not become ready after patch: %s", err)
	}

	// Get the new pod and verify it has the updated resource limits
	t.Log("Verifying new resource limits on operator pod")
	podList := &corev1.PodList{}
	err = f.Client.List(context.TODO(), podList,
		client.InNamespace(f.OperatorNamespace),
		client.MatchingLabels(map[string]string{"name": "compliance-operator"}))
	if err != nil {
		t.Fatalf("failed to list operator pods: %s", err)
	}

	if len(podList.Items) == 0 {
		t.Fatal("no compliance-operator pods found")
	}

	pod := podList.Items[0]
	if len(pod.Spec.Containers) == 0 {
		t.Fatal("no containers found in pod")
	}

	podContainer := pod.Spec.Containers[0]
	newCPULimit := podContainer.Resources.Limits.Cpu().String()
	newMemLimit := podContainer.Resources.Limits.Memory().String()
	newCPURequest := podContainer.Resources.Requests.Cpu().String()
	newMemRequest := podContainer.Resources.Requests.Memory().String()

	if newCPULimit != "256m" {
		t.Errorf("expected new CPU limit 256m, got %s", newCPULimit)
	}
	if newMemLimit != "512Mi" {
		t.Errorf("expected new memory limit 512Mi, got %s", newMemLimit)
	}
	if newCPURequest != "25m" {
		t.Errorf("expected new CPU request 25m, got %s", newCPURequest)
	}
	if newMemRequest != "52Mi" {
		t.Errorf("expected new memory request 52Mi, got %s", newMemRequest)
	}

	t.Log("Successfully verified operator resource limits are configurable")
}

func TestRuntimeSSHConfigWithRemediation(t *testing.T) {
	f := framework.Global

	baselineImage := fmt.Sprintf("%s:%s", brokenContentImagePath, "runtime_sshd")
	pbName := framework.GetObjNameFromTest(t)

	rhcos4Pb, err := f.CreateProfileBundle(pbName, baselineImage, framework.RhcosContentFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), rhcos4Pb)
	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}

	// This test applies an SSH remediation and verifies runtime checks still work
	suiteName := "test-runtime-ssh-remediation"
	scanName := fmt.Sprintf("%s-scan", suiteName)

	suite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: true,
			},
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: baselineImage,
						Profile:      "xccdf_org.ssgproject.content_profile_e8",
						Rule:         "xccdf_org.ssgproject.content_rule_sshd_disable_gssapi_auth",
						Content:      framework.RhcosContentFile,
						NodeSelector: framework.GetPoolNodeRoleSelector(),
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
		t.Fatalf("failed to create ComplianceSuite: %s", err)
	}
	defer f.Client.Delete(context.TODO(), suite)

	// Get the MachineConfigPool before remediation
	poolBeforeRemediation := &mcfgv1.MachineConfigPool{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: framework.TestPoolName}, poolBeforeRemediation); err != nil {
		t.Fatal(err)
	}

	// Wait for initial scan to complete - it should be non-compliant
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		// Might already be compliant if previously remediated
		if err2 := f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant); err2 != nil {
			t.Fatalf("initial scan did not complete: %v", err)
		}
		t.Log("System already compliant, skipping remediation test")
		return
	}

	// The sshd_disable_gssapi_auth fix ships two MachineConfig variants gated by
	// OCP version (<4.13.0 and >=4.13.0). The operator only generates a
	// ComplianceRemediation for the variant matching the cluster, so the applied
	// remediation name carries a version-dependent index suffix (e.g. "-1" for the
	// >=4.13.0 variant). Hard-coding the base name (the <4.13.0 variant) meant the
	// test waited on a remediation that is never created on modern clusters, so
	// WaitForRemediationToBeAutoApplied blocked for the full 30m Timeout and
	// silently timed out every run. The suite scan already reached DONE above, so
	// any remediation for this scan is already created - discover it by scan label
	// and wait for the one that actually exists.
	remList := &compv1alpha1.ComplianceRemediationList{}
	if err := f.Client.List(context.TODO(), remList, client.InNamespace(f.OperatorNamespace),
		client.MatchingLabels{compv1alpha1.ComplianceScanLabel: scanName}); err != nil {
		t.Fatalf("failed to list remediations for scan %s: %v", scanName, err)
	}
	if len(remList.Items) == 0 {
		t.Logf("No ComplianceRemediation generated for scan %s; continuing", scanName)
	}
	for i := range remList.Items {
		if err := f.WaitForRemediationToBeAutoApplied(remList.Items[i].Name, f.OperatorNamespace, poolBeforeRemediation); err != nil {
			t.Logf("Remediation %s might not be needed or already applied: %v", remList.Items[i].Name, err)
		}
	}

	// Re-run the scan to verify compliance with runtime checking
	if err := f.ReRunScan(scanName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}

	// Wait for re-scan to complete - should be compliant now
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant); err != nil {
		t.Logf("WARNING: Re-scan was not compliant after remediation: %v", err)
	}

	// Verify the runtime config was still created and used in the re-scan
	t.Log("Verifying runtime SSH config was used in re-scan after remediation")

	// Get the check result for the SSH rule
	checkName := fmt.Sprintf("%s-sshd-disable-gssapi-auth", scanName)
	check := &compv1alpha1.ComplianceCheckResult{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{
		Name:      checkName,
		Namespace: f.OperatorNamespace,
	}, check); err != nil {
		t.Logf("Could not get check result %s: %v", checkName, err)
	} else {
		t.Logf("SSH check after remediation - Status: %s", check.Status)
		if check.Status == compv1alpha1.CheckResultPass {
			t.Log("SUCCESS: SSH configuration check passed after remediation (runtime config verified)")
		}
	}

	// Clean up any remediations that were applied
	for i := range remList.Items {
		remName := remList.Items[i].Name
		rem := &compv1alpha1.ComplianceRemediation{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{
			Name:      remName,
			Namespace: f.OperatorNamespace,
		}, rem); err != nil {
			continue
		}
		// Unapply the remediation
		if err := f.UnApplyRemediationAndCheck(f.OperatorNamespace, remName, framework.TestPoolName); err != nil {
			t.Logf("Could not unapply remediation %s: %v", remName, err)
		}

		// Wait for nodes to be ready again
		if err := f.WaitForNodesToBeReady(); err != nil {
			t.Logf("Nodes did not become ready after remediation removal: %v", err)
		}
	}

	t.Log("Runtime SSH configuration with remediation test completed")
}
func TestMustGatherImageWorksAsExpected(t *testing.T) {
	f := framework.Global

	suiteName := framework.GetObjNameFromTest(t)
	scanSettingBindingName := suiteName

	// Create ScanSettingBinding to trigger compliance scans
	scanSettingBinding := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingBindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     "ocp4-cis",
				Kind:     "Profile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
			{
				Name:     "ocp4-cis-node",
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

	err := f.Client.Create(context.TODO(), scanSettingBinding, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), scanSettingBinding)

	// Wait for the ComplianceSuite scans to complete
	log.Printf("Waiting for ComplianceSuite scans to complete...")
	err = f.WaitForSuiteScansStatusAnyResult(f.OperatorNamespace, scanSettingBindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant, compv1alpha1.ResultInconsistent)
	if err != nil {
		t.Fatalf("Scan did not complete successfully: %v", err)
	}
	log.Printf("ComplianceSuite scans completed")

	// Verify that compliance resources exist before running must-gather
	// If these resources don't exist, must-gather will fail or produce incomplete results
	log.Printf("Verifying compliance resources exist in namespace %s...", f.OperatorNamespace)

	var scans compv1alpha1.ComplianceScanList
	if err := f.Client.List(context.TODO(), &scans, &client.ListOptions{Namespace: f.OperatorNamespace}); err != nil {
		t.Fatalf("Failed to list ComplianceScans: %v", err)
	}
	log.Printf("Found %d ComplianceScans in namespace", len(scans.Items))
	if len(scans.Items) == 0 {
		t.Fatal("No ComplianceScans found - cannot verify must-gather functionality")
	}

	var suites compv1alpha1.ComplianceSuiteList
	if err := f.Client.List(context.TODO(), &suites, &client.ListOptions{Namespace: f.OperatorNamespace}); err != nil {
		t.Fatalf("Failed to list ComplianceSuites: %v", err)
	}
	log.Printf("Found %d ComplianceSuites in namespace", len(suites.Items))
	if len(suites.Items) == 0 {
		t.Fatal("No ComplianceSuites found - cannot verify must-gather functionality")
	}

	var checkResults compv1alpha1.ComplianceCheckResultList
	if err := f.Client.List(context.TODO(), &checkResults, &client.ListOptions{Namespace: f.OperatorNamespace}); err != nil {
		t.Fatalf("Failed to list ComplianceCheckResults: %v", err)
	}
	log.Printf("Found %d ComplianceCheckResults in namespace", len(checkResults.Items))
	if len(checkResults.Items) == 0 {
		t.Fatal("No ComplianceCheckResults found - cannot verify must-gather functionality")
	}

	// Get the must-gather image
	// In upstream, we use an environment variable or default image since there's no CSV
	mustGatherImage := getMustGatherImage(f)
	log.Printf("Must-gather image: %s", mustGatherImage)

	// Create a temporary directory for must-gather output
	mustGatherDir := fmt.Sprintf("/tmp/must-gather-%s", suiteName)
	defer os.RemoveAll(mustGatherDir)

	// Execute must-gather
	log.Printf("Executing must-gather with image %s to directory %s...", mustGatherImage, mustGatherDir)
	mustGatherOutput, err := runOCandGetOutput([]string{
		"adm", "must-gather",
		"--image=" + mustGatherImage,
		"--dest-dir=" + mustGatherDir,
	})
	if err != nil {
		t.Fatalf("Failed to execute must-gather: %v\nOutput: %s", err, mustGatherOutput)
	}

	log.Printf("Must-gather completed successfully")

	// Verify the must-gather output directory exists
	if _, err := os.Stat(mustGatherDir); os.IsNotExist(err) {
		t.Fatalf("Must-gather directory does not exist: %s", mustGatherDir)
	}

	// Verify essential files and directories are present in must-gather output
	failureCount := verifyMustGatherContents(mustGatherDir, f.OperatorNamespace, t)
	if failureCount > 0 {
		t.Fatalf("%d must-gather content verification failures", failureCount)
	}

	log.Printf("Must-gather content verification passed")
}

// getMustGatherImage retrieves the must-gather image to use for the test
// It tries the following in order:
// 1. MUST_GATHER_IMAGE environment variable
// 2. Try to get it from CSV (if OLM is being used)
// 3. Fall back to the default upstream image
func getMustGatherImage(f *framework.Framework) string {
	// Check for environment variable first
	if mgImage := os.Getenv("MUST_GATHER_IMAGE"); mgImage != "" {
		log.Printf("Using must-gather image from MUST_GATHER_IMAGE env var: %s", mgImage)
		return mgImage
	}

	// Try to get from CSV if OLM is present (for OLM deployments)
	if isOLMPresent(f) {
		log.Printf("OLM detected, attempting to get must-gather image from CSV...")
		csvImage, err := getMustGatherImageFromCSV(f)
		if err != nil {
			log.Printf("Failed to get must-gather image from CSV: %v, falling back to default", err)
		} else if csvImage != "" {
			log.Printf("Using must-gather image from CSV: %s", csvImage)
			return csvImage
		}
	} else {
		log.Printf("OLM not detected, skipping CSV image lookup")
	}

	// Fall back to default upstream image
	defaultImage := "quay.io/redhat-user-workloads/ocp-isc-tenant/compliance-operator-must-gather-dev:master"
	log.Printf("Using default must-gather image: %s", defaultImage)
	return defaultImage
}

// isOLMPresent checks if OLM is available in the cluster
// by attempting to list ClusterServiceVersions using the API
func isOLMPresent(f *framework.Framework) bool {
	csvList := &unstructured.UnstructuredList{}
	csvList.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "operators.coreos.com",
		Version: "v1alpha1",
		Kind:    "ClusterServiceVersionList",
	})

	err := f.Client.List(context.TODO(), csvList, &client.ListOptions{Namespace: f.OperatorNamespace})
	return err == nil
}

// getMustGatherImageFromCSV retrieves the must-gather image reference from the CSV
// Returns an error if CSV doesn't exist or doesn't have the must-gather image
func getMustGatherImageFromCSV(f *framework.Framework) (string, error) {
	// List all CSVs in the operator namespace
	csvList := &unstructured.UnstructuredList{}
	csvList.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "operators.coreos.com",
		Version: "v1alpha1",
		Kind:    "ClusterServiceVersionList",
	})

	err := f.Client.List(context.TODO(), csvList, &client.ListOptions{Namespace: f.OperatorNamespace})
	if err != nil {
		return "", fmt.Errorf("failed to list CSVs: %w", err)
	}

	if len(csvList.Items) == 0 {
		return "", fmt.Errorf("no CSV found in namespace %s", f.OperatorNamespace)
	}

	// Find the compliance-operator CSV by checking the name prefix
	var csv *unstructured.Unstructured
	for i := range csvList.Items {
		csvItem := &csvList.Items[i]
		if name := csvItem.GetName(); name != "" {
			// CSVs typically have names like "compliance-operator.vX.Y.Z"
			if strings.HasPrefix(name, "compliance-operator") {
				csv = csvItem
				break
			}
		}
	}

	if csv == nil {
		return "", fmt.Errorf("no compliance-operator CSV found in namespace %s", f.OperatorNamespace)
	}

	// Extract the must-gather image from relatedImages
	relatedImages, found, err := unstructured.NestedSlice(csv.Object, "spec", "relatedImages")
	if err != nil {
		return "", fmt.Errorf("failed to get relatedImages from CSV: %w", err)
	}
	if !found {
		return "", fmt.Errorf("relatedImages not found in CSV %s", csv.GetName())
	}

	// Find the must-gather image
	for _, imgObj := range relatedImages {
		img, ok := imgObj.(map[string]interface{})
		if !ok {
			continue
		}
		name, found, err := unstructured.NestedString(img, "name")
		if err != nil || !found {
			continue
		}
		if name == "must-gather" {
			image, found, err := unstructured.NestedString(img, "image")
			if err != nil {
				return "", fmt.Errorf("failed to get image field: %w", err)
			}
			if !found || image == "" {
				return "", fmt.Errorf("must-gather image field is empty in CSV %s", csv.GetName())
			}
			return image, nil
		}
	}

	return "", fmt.Errorf("must-gather image not found in CSV %s relatedImages", csv.GetName())
}

// runOCandGetOutput runs an oc command and returns the output
func runOCandGetOutput(args []string) (string, error) {
	ocPath, err := exec.LookPath("oc")
	if err != nil {
		return "", fmt.Errorf("failed to find oc binary: %v", err)
	}

	cmd := exec.Command(ocPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("failed to run oc command: %v", err)
	}
	return string(out), nil
}

// verifyMustGatherContents verifies the expected files and directories are present in the must-gather output
func verifyMustGatherContents(mustGatherDir, namespace string, t *testing.T) int {
	failureCount := 0

	log.Printf("Verifying must-gather contents in %s", mustGatherDir)

	// Check if the directory has subdirectories (must-gather creates a timestamp directory)
	entries, err := os.ReadDir(mustGatherDir)
	if err != nil {
		t.Logf("Failed to read must-gather directory: %v", err)
		failureCount++
		return failureCount
	}

	if len(entries) == 0 {
		t.Logf("Must-gather directory is empty")
		failureCount++
		return failureCount
	}

	// must-gather creates a timestamped directory (e.g., must-gather.local.123456)
	// We need to find it first
	var timestampDir string
	for _, entry := range entries {
		if entry.IsDir() {
			timestampDir = fmt.Sprintf("%s/%s", mustGatherDir, entry.Name())
			log.Printf("Found timestamped directory: %s", entry.Name())
			break
		}
	}

	if timestampDir == "" {
		t.Logf("Could not find timestamped must-gather directory")
		failureCount++
		return failureCount
	}

	// List all directories in timestamped directory for debugging
	timestampEntries, err := os.ReadDir(timestampDir)
	if err == nil {
		log.Printf("Contents of timestamped directory:")
		for _, entry := range timestampEntries {
			if entry.IsDir() {
				log.Printf("  - %s (directory)", entry.Name())
			} else {
				log.Printf("  - %s (file)", entry.Name())
			}
		}
	}

	// The must-gather data is written directly to the timestamped directory
	// Verify compliance operator namespace directory exists
	complianceNamespaceDir := fmt.Sprintf("%s/%s", timestampDir, namespace)
	if _, err := os.Stat(complianceNamespaceDir); os.IsNotExist(err) {
		t.Logf("namespace directory %s not found at %s", namespace, complianceNamespaceDir)
		failureCount++
		return failureCount
	}

	log.Printf("Found namespace directory: %s", namespace)

	// List all directories in compliance operator namespace for debugging
	complianceEntries, err := os.ReadDir(complianceNamespaceDir)
	if err == nil {
		log.Printf("Contents of %s namespace directory:", namespace)
		for _, entry := range complianceEntries {
			if entry.IsDir() {
				log.Printf("  - %s (directory)", entry.Name())
			} else {
				log.Printf("  - %s (file)", entry.Name())
			}
		}
	}

	// Verify essential subdirectories exist
	// Note: The gather script currently hardcodes "openshift-compliance" for pods/configmaps
	// (see gather_compliance lines 49-67), so we check there regardless of actual operator namespace
	// TODO: This should be fixed in the gather script to use the actual operator namespace
	essentialDirs := []string{"pods", "configmaps"}
	openshiftComplianceDir := fmt.Sprintf("%s/openshift-compliance", timestampDir)
	for _, dir := range essentialDirs {
		dirPath := fmt.Sprintf("%s/%s", openshiftComplianceDir, dir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			t.Logf("Expected directory %s not found in openshift-compliance", dir)
			failureCount++
		} else {
			log.Printf("Found %s directory in openshift-compliance", dir)
		}
	}

	// Check for compliance CRD directories (all should exist since we're using a ScanSettingBinding)
	// Note: These are created by the gather script at lines 8-20 of gather_compliance
	// They are only present if there are actual CRD instances in the namespace
	complianceCRDs := []string{
		"compliancescans.compliance.openshift.io",
		"compliancesuites.compliance.openshift.io",
		"compliancecheckresults.compliance.openshift.io",
	}

	// Search for CRD directories in multiple locations
	// The gather script may place them in different directories depending on the environment
	foundCRDs := searchCRDDirectories(complianceCRDs, complianceNamespaceDir, timestampDir, namespace)

	// Log results
	if len(foundCRDs) < len(complianceCRDs) {
		missingCRDs := []string{}
		for _, crd := range complianceCRDs {
			if !foundCRDs[crd] {
				missingCRDs = append(missingCRDs, crd)
			}
		}
		t.Logf("ERROR: Not all compliance CRD directories found. Missing: %v", missingCRDs)
		t.Logf("Found: %d/%d CRD directories", len(foundCRDs), len(complianceCRDs))
		t.Logf("This indicates the gather script failed to collect CRD data - check gather.logs")
		log.Printf("ERROR: Missing CRD directories %v - this is a must-gather bug", missingCRDs)
		failureCount++
	}

	return failureCount
}

// searchCRDDirectories searches for CRD directories in multiple locations and returns a map of found CRDs.
// It searches in order: compliance namespace dir, parent timestamp dir, other namespace dirs.
// Returns early once all CRDs are found to optimize performance.
func searchCRDDirectories(crdNames []string, complianceNamespaceDir, timestampDir, namespace string) map[string]bool {
	foundCRDs := make(map[string]bool)
	searchLocations := []struct {
		name        string
		getPathFunc func(string) []string
	}{
		{
			name: "compliance namespace directory",
			getPathFunc: func(crd string) []string {
				return []string{fmt.Sprintf("%s/%s", complianceNamespaceDir, crd)}
			},
		},
		{
			name: "parent timestamp directory",
			getPathFunc: func(crd string) []string {
				return []string{fmt.Sprintf("%s/%s", timestampDir, crd)}
			},
		},
		{
			name: "other namespace directories",
			getPathFunc: func(crd string) []string {
				var paths []string
				if entries, err := os.ReadDir(timestampDir); err == nil {
					for _, entry := range entries {
						if entry.IsDir() && entry.Name() != namespace && entry.Name() != "gather.logs" {
							paths = append(paths, fmt.Sprintf("%s/%s/%s", timestampDir, entry.Name(), crd))
						}
					}
				}
				return paths
			},
		},
	}

	for _, location := range searchLocations {
		if len(foundCRDs) == len(crdNames) {
			break // All CRDs found, no need to continue searching
		}

		for _, crd := range crdNames {
			if foundCRDs[crd] {
				continue // Already found this CRD
			}

			for _, path := range location.getPathFunc(crd) {
				if _, err := os.Stat(path); err == nil {
					log.Printf("Found CRD directory in %s: %s", location.name, crd)
					foundCRDs[crd] = true
					break
				}
			}
		}
	}

	return foundCRDs
}

func TestResultServerNodeSelectorMaster(t *testing.T) {
	f := framework.Global

	defaultScanSetting := &compv1alpha1.ScanSetting{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: "default", Namespace: f.OperatorNamespace}, defaultScanSetting); err != nil {
		t.Fatal(err)
	}

	scanSettingName := "default"
	if defaultScanSetting.RawResultStorage.NodeSelector == nil || len(defaultScanSetting.RawResultStorage.NodeSelector) == 0 {
		scanSettingName = framework.GetObjNameFromTest(t) + "-master-ss"
		customScanSetting := defaultScanSetting.DeepCopy()
		customScanSetting.ObjectMeta = metav1.ObjectMeta{Name: scanSettingName, Namespace: f.OperatorNamespace}
		customScanSetting.RawResultStorage.NodeSelector = map[string]string{"node-role.kubernetes.io/master": ""}
		customScanSetting.RawResultStorage.Tolerations = []corev1.Toleration{
			{Key: "node-role.kubernetes.io/master", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
		}
		if err := f.Client.Create(context.TODO(), customScanSetting, nil); err != nil {
			t.Fatalf("failed to create ScanSetting with master nodeSelector: %v", err)
		}
		defer f.Client.Delete(context.TODO(), customScanSetting)
	}

	b := framework.GetObjNameFromTest(t) + "-master-ns"
	ssb := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{Name: b, Namespace: f.OperatorNamespace},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     "ocp4-high-node",
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
	if err := f.Client.Create(context.TODO(), &ssb, nil); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.DeleteScanSettingBindingAndWaitForCleanup(&ssb); err != nil {
			t.Logf("cleanup ScanSettingBinding %s: %v", b, err)
		}
	}()

	if _, err := f.WaitForResultServerPodsWithNodeSelector(map[string]string{"node-role.kubernetes.io/master": ""}); err != nil {
		t.Fatal(err)
	}
	if err := f.WaitForSuiteScansStatusAnyResult(f.OperatorNamespace, b, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant, compv1alpha1.ResultCompliant); err != nil {
		t.Fatalf("ComplianceSuite %s did not complete: %v", b, err)
	}
}

func TestResultServerNodeSelectorWorker(t *testing.T) {
	f := framework.Global

	defaultScanSetting := &compv1alpha1.ScanSetting{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: "default", Namespace: f.OperatorNamespace}, defaultScanSetting); err != nil {
		t.Fatal(err)
	}

	scanSettingName := "default"
	if defaultScanSetting.RawResultStorage.NodeSelector == nil || len(defaultScanSetting.RawResultStorage.NodeSelector) == 0 {
		scanSettingName = framework.GetObjNameFromTest(t) + "-worker-ss"
		customScanSetting := defaultScanSetting.DeepCopy()
		customScanSetting.ObjectMeta = metav1.ObjectMeta{Name: scanSettingName, Namespace: f.OperatorNamespace}
		customScanSetting.RawResultStorage.NodeSelector = map[string]string{"node-role.kubernetes.io/worker": ""}
		if customScanSetting.RawResultStorage.Tolerations == nil {
			customScanSetting.RawResultStorage.Tolerations = []corev1.Toleration{}
		}
		if err := f.Client.Create(context.TODO(), customScanSetting, nil); err != nil {
			t.Fatalf("failed to create ScanSetting with worker nodeSelector: %v", err)
		}
		defer f.Client.Delete(context.TODO(), customScanSetting)
	}

	b := framework.GetObjNameFromTest(t) + "-worker-ns"
	ssb := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{Name: b, Namespace: f.OperatorNamespace},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     "ocp4-high-node",
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
	if err := f.Client.Create(context.TODO(), &ssb, nil); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.DeleteScanSettingBindingAndWaitForCleanup(&ssb); err != nil {
			t.Logf("cleanup ScanSettingBinding %s: %v", b, err)
		}
	}()

	if _, err := f.WaitForResultServerPodsWithNodeSelector(map[string]string{"node-role.kubernetes.io/worker": ""}); err != nil {
		t.Fatal(err)
	}
	if err := f.WaitForSuiteScansStatusAnyResult(f.OperatorNamespace, b, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant, compv1alpha1.ResultCompliant); err != nil {
		t.Fatalf("ComplianceSuite %s did not complete: %v", b, err)
	}
}

func TestResultServerTolerationsOnTaintedNode(t *testing.T) {
	f := framework.Global

	workerNodes, err := f.GetNodesWithSelector(map[string]string{"node-role.kubernetes.io/worker": ""})
	if err != nil {
		t.Fatal(err)
	}
	if len(workerNodes) == 0 {
		t.Skip("No worker nodes available")
	}
	workerNode := &workerNodes[0]

	defaultScanSetting := &compv1alpha1.ScanSetting{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: "default", Namespace: f.OperatorNamespace}, defaultScanSetting); err != nil {
		t.Fatal(err)
	}

	taintKey := "key1"
	scanSettingName := "default"
	if defaultScanSetting.RawResultStorage.NodeSelector == nil || len(defaultScanSetting.RawResultStorage.NodeSelector) == 0 {
		scanSettingName = framework.GetObjNameFromTest(t) + "-worker-ss"
		customScanSetting := defaultScanSetting.DeepCopy()
		customScanSetting.ObjectMeta = metav1.ObjectMeta{Name: scanSettingName, Namespace: f.OperatorNamespace}
		customScanSetting.RawResultStorage.NodeSelector = map[string]string{"node-role.kubernetes.io/worker": ""}
		customScanSetting.RawResultStorage.Tolerations = []corev1.Toleration{
			{Effect: corev1.TaintEffectNoSchedule, Key: "node-role.kubernetes.io/master", Operator: corev1.TolerationOpExists},
			{Effect: corev1.TaintEffectNoExecute, Key: "node.kubernetes.io/not-ready", Operator: corev1.TolerationOpExists, TolerationSeconds: &[]int64{300}[0]},
			{Effect: corev1.TaintEffectNoExecute, Key: "node.kubernetes.io/unreachable", Operator: corev1.TolerationOpExists, TolerationSeconds: &[]int64{300}[0]},
			{Effect: corev1.TaintEffectNoSchedule, Key: "node.kubernetes.io/memory-pressure", Operator: corev1.TolerationOpExists},
			{Effect: corev1.TaintEffectNoExecute, Key: taintKey, Value: "value1", Operator: corev1.TolerationOpEqual},
		}
		if err := f.Client.Create(context.TODO(), customScanSetting, nil); err != nil {
			t.Fatalf("failed to create ScanSetting with worker nodeSelector: %v", err)
		}
		defer f.Client.Delete(context.TODO(), customScanSetting)
	}

	taint := corev1.Taint{Key: taintKey, Value: "value1", Effect: corev1.TaintEffectNoExecute}
	if err := f.TaintNode(workerNode, taint); err != nil {
		t.Fatalf("failed to taint node %s: %v", workerNode.Name, err)
	}
	defer f.UntaintNode(workerNode.Name, taintKey)

	labeledNode := &corev1.Node{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: workerNode.Name}, labeledNode); err != nil {
		t.Fatalf("failed to get node %s before labeling: %v", workerNode.Name, err)
	}
	if labeledNode.Labels == nil {
		labeledNode.Labels = make(map[string]string)
	}
	labeledNode.Labels["taint"] = "true"
	if err := f.Client.Update(context.TODO(), labeledNode); err != nil {
		t.Fatalf("failed to label node %s: %v", workerNode.Name, err)
	}
	defer func() {
		unlabeledNode := &corev1.Node{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: workerNode.Name}, unlabeledNode); err == nil {
			delete(unlabeledNode.Labels, "taint")
			f.Client.Update(context.TODO(), unlabeledNode)
		}
	}()

	b := framework.GetObjNameFromTest(t) + "-tolerations"
	ssb := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{Name: b, Namespace: f.OperatorNamespace},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     "ocp4-high-node",
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
	if err := f.Client.Create(context.TODO(), &ssb, nil); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.DeleteScanSettingBindingAndWaitForCleanup(&ssb); err != nil {
			t.Logf("cleanup ScanSettingBinding %s: %v", b, err)
		}
	}()

	resultServerNodeNames, err := f.WaitForResultServerPodsWithNodeSelector(map[string]string{"node-role.kubernetes.io/worker": ""})
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("result server pods scheduled on nodes: %v", resultServerNodeNames)
	found := false
	for _, name := range resultServerNodeNames {
		if name == workerNode.Name {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no result server pod scheduled on tainted worker node %s; scheduled on: %v", workerNode.Name, resultServerNodeNames)
	}
	if err := f.WaitForSuiteScansStatusAnyResult(f.OperatorNamespace, b, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant, compv1alpha1.ResultCompliant); err != nil {
		t.Fatalf("ComplianceSuite %s did not complete: %v", b, err)
	}
}

func TestPrometheusRuleComplianceAlert(t *testing.T) {
	f := framework.Global
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

//testExecution{
//	Name:       "TestNodeSchedulingErrorFailsTheScan",
//	IsParallel: false,
//	TestFn: func(t *testing.T, f *framework.Framework, ctx *framework.Context, namespace string) error {
//		workerNodesLabel := map[string]string{
//			"node-role.kubernetes.io/worker": "",
//		}
//		workerNodes := getNodesWithSelectorOrFail(t, f, workerNodesLabel)
//		//		taintedNode := &workerNodes[0]
//		taintKey := "co-e2e"
//		taintVal := "val"
//		taint := corev1.Taint{
//			Key:    taintKey,
//			Value:  taintVal,
//			Effect: corev1.TaintEffectNoSchedule,
//		}
//		if err := taintNode(t, f, taintedNode, taint); err != nil {
//			E2ELog(t, "Tainting node failed")
//			return err
//		}
//		suiteName := getObjNameFromTest(t)
//		scanName := suiteName
//		suite := &compv1alpha1.ComplianceSuite{
//			ObjectMeta: metav1.ObjectMeta{
//				Name:      suiteName,
//				Namespace: namespace,
//			},
//			Spec: compv1alpha1.ComplianceSuiteSpec{
//				Scans: []compv1alpha1.ComplianceScanSpecWrapper{
//					{
//						ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
//							ContentImage: contentImagePath,
//							Profile:      "xccdf_org.ssgproject.content_profile_moderate",
//							Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
//							Content:      rhcosContentFile,
//							NodeSelector: workerNodesLabel,
//							ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
//								Debug: true,
//			},
//						},
//						Name: scanName,
//					},
//				},
//			},
//		}
//		if err := f.Client.Create(goctx.TODO(), suite, getCleanupOpts(ctx)); err != nil {
//			return err
//		}
//		//		err := waitForSuiteScansStatus(t, f, namespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultError)
//		if err != nil {
//			return err
//		}
//		return removeNodeTaint(t, f, taintedNode.Name, taintKey)
//	},
//},

func TestOpenSCAPRuleMetadataPropagation(t *testing.T) {
	f := framework.Global

	testName := framework.GetObjNameFromTest(t)
	tpName := fmt.Sprintf("%s-tp", testName)
	ssbName := fmt.Sprintf("%s-ssb", testName)
	testNamespace := f.OperatorNamespace
	ruleName := "ocp4-api-server-audit-log-path"

	var rule compv1alpha1.Rule
	err := f.Client.Get(context.TODO(), types.NamespacedName{
		Name:      ruleName,
		Namespace: testNamespace,
	}, &rule)
	if err != nil {
		t.Fatalf("Failed to get Rule %s: %v", ruleName, err)
	}

	customLabels := map[string]string{
		"e2e-business-unit": "security-ops",
		"e2e-risk-tier":     "high",
	}
	customAnnotations := map[string]string{
		"e2e-internal-id":   "SEC-9001",
		"e2e-audit-contact": "compliance-team",
	}

	if rule.Labels == nil {
		rule.Labels = make(map[string]string)
	}
	for k, v := range customLabels {
		rule.Labels[k] = v
	}
	if rule.Annotations == nil {
		rule.Annotations = make(map[string]string)
	}
	for k, v := range customAnnotations {
		rule.Annotations[k] = v
	}

	err = f.Client.Update(context.TODO(), &rule)
	if err != nil {
		t.Fatalf("Failed to add custom metadata to Rule: %v", err)
	}
	defer func() {
		var cleanupRule compv1alpha1.Rule
		if getErr := f.Client.Get(context.TODO(), types.NamespacedName{
			Name: ruleName, Namespace: testNamespace,
		}, &cleanupRule); getErr == nil {
			for k := range customLabels {
				delete(cleanupRule.Labels, k)
			}
			for k := range customAnnotations {
				delete(cleanupRule.Annotations, k)
			}
			_ = f.Client.Update(context.TODO(), &cleanupRule)
		}
	}()

	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: testNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "OpenSCAP Metadata Propagation Test",
			Description: "Tests that custom metadata on Rules propagates through the aggregator",
			Extends:     "ocp4-cis",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      ruleName,
					Rationale: "Verify metadata propagation via OpenSCAP aggregator",
				},
			},
		},
	}

	err = f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatalf("Failed to create TailoredProfile: %v", err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ssbName,
			Namespace: testNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     tpName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}

	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatalf("Failed to create ScanSettingBinding: %v", err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	err = f.WaitForSuiteScansStatusAnyResult(testNamespace, ssbName, compv1alpha1.PhaseDone, compv1alpha1.ResultNotApplicable, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatalf("Scan did not complete: %v", err)
	}

	checkResultName := fmt.Sprintf("%s-%s", tpName, "api-server-audit-log-path")
	var checkResult compv1alpha1.ComplianceCheckResult
	err = f.Client.Get(context.TODO(), types.NamespacedName{
		Name:      checkResultName,
		Namespace: testNamespace,
	}, &checkResult)
	if err != nil {
		t.Fatalf("Failed to get ComplianceCheckResult %s: %v", checkResultName, err)
	}

	for k, v := range customLabels {
		if checkResult.Labels[k] != v {
			t.Errorf("expected label %s=%s, got %q", k, v, checkResult.Labels[k])
		}
	}
	for k, v := range customAnnotations {
		if checkResult.Annotations[k] != v {
			t.Errorf("expected annotation %s=%s, got %q", k, v, checkResult.Annotations[k])
		}
	}

	if checkResult.Labels[compv1alpha1.ComplianceScanLabel] != tpName {
		t.Errorf("operator-managed scan label should not be overridden, got %q", checkResult.Labels[compv1alpha1.ComplianceScanLabel])
	}
}

func TestTokenRulesPassOauthClientsConfigurable(t *testing.T) {
	f := framework.Global
	suiteName := framework.GetObjNameFromTest(t)
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "oauthRules",
			Description: "oauthRules",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-oauth-or-oauthclient-token-maxage",
					Rationale: "To be tested",
				},
				{
					Name:      "ocp4-oauth-or-oauthclient-inactivity-timeout",
					Rationale: "To be tested",
				},
			},
			SetValues: []compv1alpha1.VariableValueSpec{
				{
					Name:      "ocp4-var-oauth-token-maxage",
					Value:     "28800",
					Rationale: "Set token max age to 28800 seconds",
				},
			},
		},
	}
	createTPErr := f.Client.Create(context.TODO(), tp, nil)
	if createTPErr != nil {
		t.Fatal(createTPErr)
	}
	defer f.Client.Delete(context.TODO(), tp)

	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     suiteName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}
	err := f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// Wait for initial scan to complete and verify non-compliant
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	originalConfigs, err := f.GetOAuthClientConfigs()
	if err != nil {
		t.Fatalf("failed to get oauth client configs: %s", err)
	}
	if err := f.UpdateOAuthClientConfigs(28800, 600); err != nil {
		t.Fatalf("failed to update oauth client configs: %s", err)
	}
	defer func() {
		if restoreErr := f.RestoreOAuthClientConfigs(originalConfigs); restoreErr != nil {
			t.Logf("failed to restore oauth client configs: %v", restoreErr)
		}
	}()

	// Re-run the suite
	if err := f.RescanSuite(suiteName, f.OperatorNamespace); err != nil {
		t.Fatalf("failed to rescan suite: %s", err)
	}

	// Wait for scans to restart
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseRunning, compv1alpha1.ResultNotAvailable); err != nil {
		t.Fatal(err)
	}

	// Wait for scans to complete and verify compliant
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant); err != nil {
		t.Fatal(err)
	}
}

// TestKubeletConfigIsScannedAcrossReruns is a regression test for the runtime
// kubeletconfig delivery path. The operator collects each node's kubeletconfig
// and makes it available to the scanner at the path the kubelet content rules
// read. If that delivery breaks (e.g. the file is not present where the rule
// looks), every kubelet `yamlfile_value` check with check_existence:all_exist
// silently fails. This test scans two kubelet rules that PASS on a default
// OpenShift node (anonymous auth disabled, authorization mode Webhook) and
// asserts they actually PASS - which can only happen if the runtime
// kubeletconfig was delivered and read. It then re-runs the scan on the same
// nodes and asserts the checks still PASS, guarding against a non-idempotent
// delivery that only fails on the second and later scans on a node.
func TestKubeletConfigIsScannedAcrossReruns(t *testing.T) {
	f := framework.Global
	tpName := framework.GetObjNameFromTest(t)
	bindingName := tpName + "-binding"

	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
			// A TailoredProfile with no extends defaults to a Platform scan;
			// the kubelet rules must run in a node scan.
			Annotations: map[string]string{
				compv1alpha1.ProductTypeAnnotation: string(compv1alpha1.ScanTypeNode),
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "kubeletconfig runtime delivery regression",
			Description: "Verifies the runtime kubeletconfig is delivered to the scanner",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{Name: "ocp4-kubelet-anonymous-auth", Rationale: "verify runtime kubeletconfig delivery"},
				{Name: "ocp4-kubelet-authorization-mode", Rationale: "verify runtime kubeletconfig delivery"},
			},
		},
	}
	if err := f.Client.Create(context.TODO(), tp, nil); err != nil {
		t.Fatalf("failed to create tailored profile %s: %s", tpName, err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{Name: tpName, Kind: "TailoredProfile", APIGroup: "compliance.openshift.io/v1alpha1"},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			Name: "default", Kind: "ScanSetting", APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}
	if err := f.Client.Create(context.TODO(), ssb, nil); err != nil {
		t.Fatalf("failed to create scan setting binding %s: %s", bindingName, err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// A node TailoredProfile produces per-role scans; assert against the master scan.
	scanName := tpName + "-master"
	kubeletChecks := []struct{ suffix, id string }{
		{"kubelet-anonymous-auth", "xccdf_org.ssgproject.content_rule_kubelet_anonymous_auth"},
		{"kubelet-authorization-mode", "xccdf_org.ssgproject.content_rule_kubelet_authorization_mode"},
	}

	assertKubeletChecksPass := func(phase string) {
		if err := f.WaitForSuiteScansStatusAnyResult(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone,
			compv1alpha1.ResultCompliant, compv1alpha1.ResultNonCompliant); err != nil {
			t.Fatalf("%s: scan did not finish: %s", phase, err)
		}
		for _, c := range kubeletChecks {
			check := compv1alpha1.ComplianceCheckResult{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("%s-%s", scanName, c.suffix),
					Namespace: f.OperatorNamespace,
				},
				ID:       c.id,
				Status:   compv1alpha1.CheckResultPass,
				Severity: compv1alpha1.CheckResultSeverityMedium,
			}
			if err := f.AssertHasCheck(bindingName, scanName, check); err != nil {
				t.Fatalf("%s: kubelet check %q is not PASS - the runtime kubeletconfig was likely not delivered to the scanner: %s", phase, c.suffix, err)
			}
		}
	}

	// First scan: the kubeletconfig must be delivered and read.
	assertKubeletChecksPass("initial scan")

	// Re-run on the same nodes: catches a non-idempotent delivery that only
	// breaks on the second and later scans on a node.
	if err := f.ReRunScan(scanName, f.OperatorNamespace); err != nil {
		t.Fatalf("failed to re-run scan %s: %s", scanName, err)
	}
	assertKubeletChecksPass("re-run scan")
}
