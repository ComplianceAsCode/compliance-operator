package core_scan_e2e

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"testing"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	"k8s.io/apimachinery/pkg/api/resource"
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

func TestNonExistentDeprecatedProfile(t *testing.T) {
	t.Parallel()
	f := framework.Global

	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_non_existing_profile",
			Content:      framework.OcpContentFile,
			ContentImage: contentImagePath,
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

	// The profile deprecation warning is sent out during Pending phase
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertScanIsInError(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	if err = f.Client.Get(context.TODO(), types.NamespacedName{Name: scanName, Namespace: f.OperatorNamespace}, testScan); err != nil {
		t.Fatal(err)
	}
	if testScan.Status.ErrorMessage != "Could not check whether the Profile used by ComplianceScan is deprecated" {
		t.Fatal(errors.New("expected error message to be from failed profile deprecation check"))
	}
}

func TestScanProducesRemediationsAndLabels(t *testing.T) {
	t.Parallel()
	f := framework.Global
	bindingName := framework.GetObjNameFromTest(t)
	tpName := framework.GetObjNameFromTest(t)

	// When using a profile directly, the profile name gets re-used
	// in the scan. By using a tailored profile we ensure that
	// the scan is unique and we get no clashes.
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       t.Name(),
			Description: t.Name(),
			Extends:     "ocp4-e8",
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
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), &scanSettingBinding, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSettingBinding)
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	// Since the scan was not compliant, there should be some remediations and none
	// of them should be an error
	inNs := client.InNamespace(f.OperatorNamespace)
	withLabel := client.MatchingLabels{compv1alpha1.SuiteLabel: bindingName}
	fmt.Println(inNs, withLabel)
	remList := &compv1alpha1.ComplianceRemediationList{}
	err = f.Client.List(context.TODO(), remList, inNs, withLabel)
	if err != nil {
		t.Fatal(err)
	}

	if len(remList.Items) == 0 {
		t.Fatal("expected at least one remediation")
	}
	for _, rem := range remList.Items {
		if rem.Status.ApplicationState != compv1alpha1.RemediationNotApplied {
			t.Fatal("expected all remediations are unapplied when scan finishes")
		}
	}
	// Verify ComplianceCheckResult labels are correctly set
	// Get all checks from the suite to verify label functionality
	checkList := &compv1alpha1.ComplianceCheckResultList{}
	err = f.Client.List(context.TODO(), checkList, inNs, withLabel)
	if err != nil {
		t.Fatal(err)
	}
	if len(checkList.Items) == 0 {
		t.Fatal("expected at least one check result")
	}
	// Verify all required labels are present on every check result
	// For some labels we can verify the exact value
	labelsWithValues := map[string]string{
		compv1alpha1.SuiteLabel:          bindingName,
		compv1alpha1.ComplianceScanLabel: bindingName,
	}
	// For other labels we just verify they are present (non-empty)
	labelsPresenceOnly := []string{
		compv1alpha1.ComplianceCheckResultSeverityLabel,
		compv1alpha1.ComplianceCheckResultStatusLabel,
	}
	for _, check := range checkList.Items {
		// Check labels with specific expected values
		for label, expected := range labelsWithValues {
			if check.Labels[label] != expected {
				t.Fatalf("check %s label %s: got %q, want %q", check.Name, label, check.Labels[label], expected)
			}
		}
		// Check labels that must be present (non-empty)
		for _, label := range labelsPresenceOnly {
			if check.Labels[label] == "" {
				t.Fatalf("check %s is missing label %s", check.Name, label)
			}
		}
	}
}

func TestSingleScanWithStorageSucceeds(t *testing.T) {
	t.Parallel()
	f := framework.Global
	scanName := framework.GetObjNameFromTest(t)
	t.Logf("Creating ComplianceScan %s with storage size 2Gi", scanName)
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
				RawResultStorage: compv1alpha1.RawResultStorageSettings{
					Size: "2Gi",
				},
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testScan)
	t.Logf("Waiting for scan %s to reach phase Done", scanName)
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatalf("Scan %s did not reach Done phase: %v", scanName, err)
	}
	t.Logf("Scan %s reached Done phase", scanName)

	t.Logf("Asserting scan %s is compliant", scanName)
	err = f.AssertScanIsCompliant(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatalf("Scan %s is not compliant: %v", scanName, err)
	}
	t.Logf("Asserting scan %s has valid PVC reference with size 2Gi", scanName)
	err = f.AssertScanHasValidPVCReferenceWithSize(scanName, "2Gi", f.OperatorNamespace)
	if err != nil {
		t.Fatalf("Scan %s PVC reference check failed: %v", scanName, err)
	}
	t.Logf("Asserting ARF report exists in PVC for scan %s", scanName)
	err = f.AssertARFReportExistsInPVC(t, scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatalf("Scan %s ARF report check failed: %v", scanName, err)
	}
	t.Logf("All assertions passed for scan %s", scanName)
}

