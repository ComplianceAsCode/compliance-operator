package parallel_e2e

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"testing"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

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

func TestSingleScanSucceeds(t *testing.T) {
	t.Parallel()
	f := framework.Global

	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatalf("failed to create scan %s: %s", scanName, err)
	}
	defer f.Client.Delete(context.TODO(), testScan)

	// Verify scanner container security capabilities during running phase
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}

	// Assert scanner container has correct capabilities (drops all, only has CAP_SYS_CHROOT)
	pods, err := f.GetPodsForScan(scanName)
	if err != nil {
		t.Fatal(err)
	}
	if len(pods) < 1 {
		t.Fatal("No scanner pods found for the scan")
	}

	// Find the scanner container and verify its capabilities
	found := false
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			if container.Name == "scanner" {
				found = true
				if container.SecurityContext == nil {
					t.Fatal("Scanner container has no security context")
				}
				if container.SecurityContext.Capabilities == nil {
					t.Fatal("Scanner container has no capabilities configuration")
				}

				// Verify privileged mode is false
				if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
					t.Fatal("Expected scanner container to run in non-privileged mode")
				}

				// Verify all capabilities are dropped
				droppedCaps := container.SecurityContext.Capabilities.Drop
				if len(droppedCaps) != 1 || string(droppedCaps[0]) != "ALL" {
					t.Fatalf("Expected scanner container to drop ALL capabilities, got: %v", droppedCaps)
				}

				// Verify CAP_SYS_CHROOT and CAP_SYS_ADMIN are added
				addedCaps := container.SecurityContext.Capabilities.Add
				if len(addedCaps) != 2 {
					t.Fatalf("Expected scanner container to have CAP_SYS_CHROOT and CAP_SYS_ADMIN capabilities, got: %v", addedCaps)
				}
				hasChroot := false
				hasSysAdmin := false
				for _, cap := range addedCaps {
					if string(cap) == "CAP_SYS_CHROOT" {
						hasChroot = true
					}
					if string(cap) == "CAP_SYS_ADMIN" {
						hasSysAdmin = true
					}
				}
				if !hasChroot || !hasSysAdmin {
					t.Fatalf("Expected scanner container to have both CAP_SYS_CHROOT and CAP_SYS_ADMIN capabilities, got: %v", addedCaps)
				}
				break
			}
		}
		if found {
			break
		}
	}

	if !found {
		t.Fatal("Scanner container not found in any pod")
	}

	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertScanIsCompliant(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	aggrString := fmt.Sprintf("compliance_operator_compliance_scan_status_total{name=\"%s\",phase=\"AGGREGATING\",result=\"NOT-AVAILABLE\"}", scanName)
	metricsSet := map[string]int{
		fmt.Sprintf("compliance_operator_compliance_scan_status_total{name=\"%s\",phase=\"DONE\",result=\"COMPLIANT\"}", scanName):          1,
		fmt.Sprintf("compliance_operator_compliance_scan_status_total{name=\"%s\",phase=\"LAUNCHING\",result=\"NOT-AVAILABLE\"}", scanName): 1,
		fmt.Sprintf("compliance_operator_compliance_scan_status_total{name=\"%s\",phase=\"PENDING\",result=\"\"}", scanName):                1,
		fmt.Sprintf("compliance_operator_compliance_scan_status_total{name=\"%s\",phase=\"RUNNING\",result=\"NOT-AVAILABLE\"}", scanName):   1,
	}

	var metErr error
	// Aggregating may be variable, could be registered 1 to 3 times.
	for i := 1; i < 4; i++ {
		metricsSet[aggrString] = i
		err = framework.AssertEachMetric(f.OperatorNamespace, metricsSet)
		if err == nil {
			metErr = nil
			break
		}
		metErr = err
	}

	if metErr != nil {
		t.Fatalf("failed to assert metrics for scan %s: %s\n", scanName, metErr)
	}

	err = f.AssertScanHasValidPVCReference(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatalf("failed to assert PVC reference for scan %s: %s", scanName, err)
	}

	// Validate exit-code is "0"
	exitCode, _, err := f.GetScanExitCodeAndErrorMsg(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
	expectedExitCode := "0"
	if exitCode != expectedExitCode {
		t.Fatalf("Expected ConfigMap exit-code to be '%s', but got: '%s'", expectedExitCode, exitCode)
	}
}

func TestSingleScanTimestamps(t *testing.T) {
	t.Parallel()
	f := framework.Global

	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatalf("failed to create scan %s: %s", scanName, err)
	}
	defer f.Client.Delete(context.TODO(), testScan)

	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	// assertComplianceCheckResultTimestamps checks that the timestamps are set
	// and that they are set to the same value of startTimestamp of the scan
	err = f.AssertComplianceCheckResultTimestamps(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	// rerun the scan
	err = f.ReRunScan(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	// assertComplianceCheckResultTimestamps checks that the timestamps are set
	// and that they are set to the same value of startTimestamp of the scan
	err = f.AssertComplianceCheckResultTimestamps(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

}

func TestScanWithInvalidProfileFails(t *testing.T) {
	t.Parallel()
	f := framework.Global
	scanName := "test-scan-w-invalid-profile"
	exampleComplianceScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_coreos-unexistent",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), exampleComplianceScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), exampleComplianceScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanIsInError(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestMissingPodInRunningState(t *testing.T) {
	t.Parallel()
	f := framework.Global
	scanName := "test-missing-pod-scan"
	exampleComplianceScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), exampleComplianceScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), exampleComplianceScan)

	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}
	pods, err := f.GetPodsForScan(scanName)
	if err != nil {
		t.Fatal(err)
	}
	if len(pods) < 1 {
		t.Fatal("No pods gotten from query for the scan")
	}
	podToDelete := pods[rand.Intn(len(pods))]
	// Delete pod ASAP
	zeroSeconds := int64(0)
	do := client.DeleteOptions{GracePeriodSeconds: &zeroSeconds}
	err = f.Client.Delete(context.TODO(), &podToDelete, &do)
	if err != nil {
		t.Fatal(err)
	}
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertScanIsCompliant(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSuiteWithContentThatDoesNotMatch(t *testing.T) {
	t.Parallel()
	f := framework.Global

	pbName := framework.GetObjNameFromTest(t)
	baselineImage := fmt.Sprintf("%s:%s", brokenContentImagePath, "broken_os_detection")
	origPb, err := f.CreateProfileBundle(pbName, baselineImage, framework.RhcosContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle: %s", err)
	}
	// This should get cleaned up at the end of the test
	defer f.Client.Delete(context.TODO(), origPb)
	if err = f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("failed waiting for the ProfileBundle to become available: %s", err)
	}

	suiteName := "test-suite-with-non-matching-content"
	testSuite := &compv1alpha1.ComplianceSuite{
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
					Name: fmt.Sprintf("%s-workers-scan", suiteName),
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: baselineImage,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      "ssg-rhcos4-ds.xml",
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug:             true,
							ShowNotApplicable: true,
						},
						NodeSelector: map[string]string{
							"node-role.kubernetes.io/worker": "",
						},
					},
				},
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err = f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNotApplicable)
	if err != nil {
		t.Fatal(err)
	}
	err = f.SuiteErrorMessageMatchesRegex(f.OperatorNamespace, suiteName, "The suite result is not applicable.*")
	if err != nil {
		t.Fatal(err)
	}
}

func TestScanCleansUpComplianceCheckResults(t *testing.T) {
	f := framework.Global
	t.Parallel()

	tpName := framework.GetObjNameFromTest(t)
	bindingName := tpName + "-binding"

	// create a tailored profile
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       tpName,
			Description: tpName,
			Extends:     "ocp4-cis",
		},
	}

	err := f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	// run a scan
	ssb := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     tpName,
				Kind:     "TailoredProfile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			Name:     "default",
			Kind:     "ScanSetting",
			APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}
	err = f.Client.Create(context.TODO(), &ssb, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &ssb)

	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	// verify a compliance check result exists
	checkName := tpName + "-audit-profile-set"
	checkResult := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      checkName,
			Namespace: f.OperatorNamespace,
		},
		ID:       "xccdf_org.ssgproject.content_rule_audit_profile_set",
		Status:   compv1alpha1.CheckResultFail,
		Severity: compv1alpha1.CheckResultSeverityMedium,
	}
	err = f.AssertHasCheck(bindingName, tpName, checkResult)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AssertRemediationExists(checkName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}

	// update tailored profile to exclude the rule before we kick off another run
	tpGet := &compv1alpha1.TailoredProfile{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: tpName, Namespace: f.OperatorNamespace}, tpGet)
	if err != nil {
		t.Fatal(err)
	}

	tpUpdate := tpGet.DeepCopy()
	ruleName := "ocp4-audit-profile-set"
	tpUpdate.Spec.DisableRules = []compv1alpha1.RuleReferenceSpec{
		{
			Name:      ruleName,
			Rationale: "testing to ensure scan results are cleaned up",
		},
	}

	err = f.Client.Update(context.TODO(), tpUpdate)
	if err != nil {
		t.Fatal(err)
	}

	// rerun the scan
	err = f.ReRunScan(tpName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	// verify the compliance check result doesn't exist, which will also
	// mean the compliance remediation should also be gone
	if err = f.AssertScanDoesNotContainCheck(tpName, checkName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}
	if err = f.AssertRemediationDoesNotExists(checkName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}
}

func TestScanWithoutBundlePassesDeprecationCheck(t *testing.T) {
	t.Parallel()
	f := framework.Global

	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile: "xccdf_org.ssgproject.content_profile_moderate",
			// Make the ProfileBundle lookup fail because the
			// Content and ContentImage mismatch. This means the
			// operator can't check if the profile is deprecated
			// because it can't reliably know which bundle it came
			// from and hasn't parsed that specific datastream. In
			// cases like this, the profile deprecation logic
			// shouldn't prevent the scan. Advanced users might use
			// this technique to point to their own custom content,
			// which is rare but possible.
			Content:      framework.OcpContentFile,
			ContentImage: contentImagePath,
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}

	// Create the scan directly since we want to set these attributes
	// directly, and not assume the existing ProfileBundles.
	err := f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatalf("failed to create scan %s: %s", scanName, err)
	}
	defer f.Client.Delete(context.TODO(), testScan)

	// Wait for the scan to reach Done phase
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	// Get the final scan state
	if err = f.Client.Get(context.TODO(), types.NamespacedName{Name: scanName, Namespace: f.OperatorNamespace}, testScan); err != nil {
		t.Fatal(err)
	}

	// The scan should NOT fail on profile deprecation check when ProfileBundle matching fails
	if testScan.Status.ErrorMessage == "Could not check whether the Profile used by ComplianceScan is deprecated" {
		t.Fatal(errors.New("scan should not fail on profile deprecation check when ProfileBundle matching fails"))
	}

	t.Logf("Scan completed with result: %s", testScan.Status.Result)
}
