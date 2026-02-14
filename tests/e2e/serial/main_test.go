package serial_e2e

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	compsuitectrl "github.com/ComplianceAsCode/compliance-operator/pkg/controller/compliancesuite"
	configv1 "github.com/openshift/api/config/v1"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func TestScanStorageOutOfQuotaRangeFails(t *testing.T) {
	f := framework.Global
	rq := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pvc-resourcequota",
			Namespace: f.OperatorNamespace,
		},
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{
				corev1.ResourceRequestsStorage: resource.MustParse("5Gi"),
			},
		},
	}
	if err := f.Client.Create(context.TODO(), rq, nil); err != nil {
		t.Fatalf("failed to create ResourceQuota: %s", err)
	}
	defer f.Client.Delete(context.TODO(), rq)

	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			ContentImage: contentImagePath,
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				RawResultStorage: compv1alpha1.RawResultStorageSettings{
					Size: "6Gi",
				},
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatalf("failed ot create scan %s: %s", scanName, err)
	}
	defer f.Client.Delete(context.TODO(), testScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertScanIsInError(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

// NOTE(jaosorior): This was made a serial test because it runs the long-running, resource-taking and
// big AF moderate profile
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

// TestSuiteScanHasCheckCounts tests that the scan has the correct check counts
func TestSuiteScanHasCheckCounts(t *testing.T) {
	f := framework.Global
	suiteName := "test-suite-two-scans-check-counts"
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
	const profileGUIDTP = "04a11c78-7c77-545e-8341-f1b7b743bcb8"
	const profileGUIDRHCOSModerate = "eceb9af0-17d4-5c59-9b17-07cfd22a3ba1"
	const profileGUIDOCPCIS = "a230315d-3e4a-5b58-b00f-f96f1553e036"

	err := f.AssertProfileGUIDMatches("ocp4-moderate", f.OperatorNamespace, profileGUIDOCPModerate)
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
	defer f.Client.Delete(context.TODO(), &scanSettingBinding)
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	// check if the profileGUID is correct in the scan's label
	err = f.AssertScanGUIDMatches("ocp4-moderate", f.OperatorNamespace, profileGUIDOCPModerate)
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

}

func TestMixProductScan(t *testing.T) {
	f := framework.Global

	// Creates a new `ScanSetting`, where the actual scan schedule doesn't necessarily matter, but `suspend` is set to `False`
	scanSettingName := framework.GetObjNameFromTest(t) + "-mixproduct"
	scanSetting := compv1alpha1.ScanSetting{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingName,
			Namespace: f.OperatorNamespace,
		},
		ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
			AutoApplyRemediations: false,
			Schedule:              "0 1 * * *",
			Suspend:               false,
		},
		ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
			Timeout: "10m",
		},
		Roles: []string{"master", "worker"},
	}
	if err := f.Client.Create(context.TODO(), &scanSetting, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSetting)

	// Bind the new ScanSetting to a Profile
	bindingName := framework.GetObjNameFromTest(t) + "-binding"
	scanSettingBinding := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
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
			Name:     scanSetting.Name,
			Kind:     "ScanSetting",
			APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}
	if err := f.Client.Create(context.TODO(), &scanSettingBinding, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSettingBinding)

	// Wait until the scan completes
	// after the scan is done
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	suite := &compv1alpha1.ComplianceSuite{}
	key := types.NamespacedName{Name: bindingName, Namespace: f.OperatorNamespace}
	if err := f.Client.Get(context.TODO(), key, suite); err != nil {
		t.Fatal(err)
	}

	// Assert all the scans are there and completed
	expectedScan := []string{"ocp4-moderate", "ocp4-moderate-node-worker", "ocp4-moderate-node-master", "rhcos4-moderate-worker", "rhcos4-moderate-master"}
	for _, scan := range expectedScan {
		found := false
		for _, s := range suite.Status.ScanStatuses {
			if s.Name == scan {
				found = true
				if s.Phase != compv1alpha1.PhaseDone {
					t.Fatalf("expected scan %s to be done", scan)
				}
				if s.Result != compv1alpha1.ResultCompliant && s.Result != compv1alpha1.ResultNonCompliant {
					t.Fatalf("expected scan %s to be compliant or non-compliant", scan)
				}
				break
			}
		}
		if !found {
			t.Fatalf("expected scan %s not found", scan)
		}
	}

}

func TestTolerations(t *testing.T) {
	f := framework.Global
	workerNodes, err := f.GetNodesWithSelector(map[string]string{
		"node-role.kubernetes.io/worker": "",
	})
	if err != nil {
		t.Fatal(err)
	}

	taintedNode := &workerNodes[0]
	taintKey := "co-e2e"
	taintVal := "val"
	taint := corev1.Taint{
		Key:    taintKey,
		Value:  taintVal,
		Effect: corev1.TaintEffectNoSchedule,
	}
	if err := f.TaintNode(taintedNode, taint); err != nil {
		t.Fatalf("failed to taint node %s: %s", taintedNode.Name, err)
	}

	removeTaintClosure := func() {
		removeTaintErr := f.UntaintNode(taintedNode.Name, taintKey)
		if removeTaintErr != nil {
			t.Fatalf("failed to remove taint: %s", removeTaintErr)
			// not much to do here
		}
	}
	defer removeTaintClosure()

	suiteName := framework.GetObjNameFromTest(t)
	scanName := suiteName
	suite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
						Content:      framework.RhcosContentFile,
						NodeSelector: map[string]string{
							// Schedule scan in this specific host
							corev1.LabelHostname: taintedNode.Labels[corev1.LabelHostname],
						},
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
							ScanTolerations: []corev1.Toleration{
								{
									Key:      taintKey,
									Operator: corev1.TolerationOpExists,
									Effect:   corev1.TaintEffectNoSchedule,
								},
							},
						},
					},
					Name: scanName,
				},
			},
		},
	}
	if err := f.Client.Create(context.TODO(), suite, nil); err != nil {
		t.Fatalf("failed to create suite %s: %s", suiteName, err)
	}
	defer f.Client.Delete(context.TODO(), suite)

	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAutoRemediate(t *testing.T) {
	f := framework.Global
	// FIXME, maybe have a func that returns a struct with suite name and scan names?
	suiteName := "test-remediate"
	scanName := fmt.Sprintf("%s-e2e", suiteName)

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
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "rhcos4-no-direct-root-logins",
					Rationale: "To be tested",
				},
			},
		},
	}

	createTPErr := f.Client.Create(context.TODO(), tp, nil)
	if createTPErr != nil {
		t.Fatalf("failed to create TailoredProfile %s: %s", tp.Name, createTPErr)
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
	err := f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatalf("failed to create ScanSettingBinding %s: %s", ssb.Name, err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// Get the MachineConfigPool before a scan or remediation has been applied
	// This way, we can check that it changed without race-conditions
	poolBeforeRemediation := &mcfgv1.MachineConfigPool{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: framework.TestPoolName}, poolBeforeRemediation)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	// We need to check that the remediation is auto-applied and save
	// the object so we can delete it later
	remName := fmt.Sprintf("%s-no-direct-root-logins", scanName)
	err = f.WaitForRemediationToBeAutoApplied(remName, f.OperatorNamespace, poolBeforeRemediation)
	if err != nil {
		t.Fatal(err)
	}

	// Fetch remediation here so we can clean up the machine config later.
	// We do this before the rescan takes place because the rescan will
	// prune the remediation after the check passes.
	rem := &compv1alpha1.ComplianceRemediation{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: remName, Namespace: f.OperatorNamespace}, rem)
	if err != nil {
		t.Fatal(err)
	}

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
	log.Printf("waiting for scan %s to finish\n", scanName)
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("scan %s re-run has finished\n", scanName)

	// Now the check should be passing
	checkNoDirectRootLogins := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-no-direct-root-logins", scanName),
			Namespace: f.OperatorNamespace,
		},
		ID:       "xccdf_org.ssgproject.content_rule_no_direct_root_logins",
		Status:   compv1alpha1.CheckResultPass,
		Severity: compv1alpha1.CheckResultSeverityMedium,
	}
	err = f.AssertHasCheck(suiteName, scanName, checkNoDirectRootLogins)
	if err != nil {
		t.Fatal(err)
	}

	// The test should not leave junk around, let's remove the MC and wait
	// for the nodes to stabilize again
	log.Printf("Removing applied machine config\n")
	mcfgToBeDeleted := rem.Spec.Current.Object.DeepCopy()
	mcfgToBeDeleted.SetName(rem.GetMcName())
	err = f.Client.Delete(context.TODO(), mcfgToBeDeleted)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("successfully deleted MachineConfig deleted, will wait for the machines to come back up")

	dummyAction := func() error {
		return nil
	}
	poolHasNoMc := func(pool *mcfgv1.MachineConfigPool) (bool, error) {
		for _, mc := range pool.Status.Configuration.Source {
			if mc.Name == rem.GetMcName() {
				return false, nil
			}
		}

		return true, nil
	}

	// We need to wait for both the pool to update..
	err = f.WaitForMachinePoolUpdate(framework.TestPoolName, dummyAction, poolHasNoMc, nil)
	if err != nil {
		t.Fatalf("failed waiting for workers to come back up after deleting MachineConfig: %s", err)
	}

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

func TestSuspendScanSetting(t *testing.T) {
	f := framework.Global

	// Creates a new `ScanSetting`, where the actual scan schedule doesn't necessarily matter, but `suspend` is set to `False`
	scanSettingName := framework.GetObjNameFromTest(t) + "-scansetting"
	scanSetting := compv1alpha1.ScanSetting{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingName,
			Namespace: f.OperatorNamespace,
		},
		ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
			AutoApplyRemediations: false,
			Schedule:              "0 1 * * *",
			Suspend:               false,
		},
		ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
			Timeout: "10m",
		},
		Roles: []string{"master", "worker"},
	}
	if err := f.Client.Create(context.TODO(), &scanSetting, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSetting)

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
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			Name:     scanSetting.Name,
			Kind:     "ScanSetting",
			APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}
	if err := f.Client.Create(context.TODO(), &scanSettingBinding, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSettingBinding)

	// Wait until the first scan completes since the CronJob is created
	// after the scan is done
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	suite := &compv1alpha1.ComplianceSuite{}
	key := types.NamespacedName{Name: bindingName, Namespace: f.OperatorNamespace}
	if err := f.Client.Get(context.TODO(), key, suite); err != nil {
		t.Fatal(err)
	}

	// Assert the CronJob is not suspended.
	if err := f.AssertCronJobIsNotSuspended(compsuitectrl.GetRerunnerName(suite.Name)); err != nil {
		t.Fatal(err)
	}
	if err := f.AssertScanSettingBindingConditionIsReady(bindingName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}

	// Suspend the `ScanSetting` using the `suspend` attribute
	scanSettingUpdate := &compv1alpha1.ScanSetting{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: f.OperatorNamespace, Name: scanSettingName}, scanSettingUpdate); err != nil {
		t.Fatalf("failed to get ScanSetting %s", scanSettingName)
	}
	scanSettingUpdate.Suspend = true
	if err := f.Client.Update(context.TODO(), scanSettingUpdate); err != nil {
		t.Fatal(err)
	}

	if err := f.WaitForScanSettingBindingStatus(f.OperatorNamespace, bindingName, compv1alpha1.ScanSettingBindingPhaseSuspended); err != nil {
		t.Fatalf("ScanSettingBinding %s failed to suspend", bindingName)
	}
	if err := f.AssertCronJobIsSuspended(compsuitectrl.GetRerunnerName(suite.Name)); err != nil {
		t.Fatal(err)
	}
	if err := f.AssertScanSettingBindingConditionIsSuspended(bindingName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}

	// Resume the `ComplianceScan` by updating the `ScanSetting.suspend` attribute to `False`
	scanSettingUpdate = &compv1alpha1.ScanSetting{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: f.OperatorNamespace, Name: scanSettingName}, scanSettingUpdate); err != nil {
		t.Fatalf("failed to get ScanSetting %s", scanSettingName)
	}
	scanSettingUpdate.Suspend = false
	if err := f.Client.Update(context.TODO(), scanSettingUpdate); err != nil {
		t.Fatal(err)
	}

	if err := f.WaitForScanSettingBindingStatus(f.OperatorNamespace, bindingName, compv1alpha1.ScanSettingBindingPhaseReady); err != nil {
		t.Fatalf("ScanSettingBinding %s failed to resume", bindingName)
	}
	if err := f.AssertCronJobIsNotSuspended(compsuitectrl.GetRerunnerName(suite.Name)); err != nil {
		t.Fatal(err)
	}
	if err := f.AssertScanSettingBindingConditionIsReady(bindingName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
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

func TestSuspendScanSettingDoesNotCreateScan(t *testing.T) {
	f := framework.Global

	// Creates a new `ScanSetting` with `suspend` set to `True`
	scanSettingName := framework.GetObjNameFromTest(t) + "-scansetting"
	scanSetting := compv1alpha1.ScanSetting{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingName,
			Namespace: f.OperatorNamespace,
		},
		ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
			AutoApplyRemediations: false,
			Schedule:              "0 1 * * *",
			Suspend:               true,
		},
		ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
			Timeout: "10m",
		},
		Roles: []string{"master", "worker"},
	}
	if err := f.Client.Create(context.TODO(), &scanSetting, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSetting)

	// Bind the new `ScanSetting` to a `Profile`
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
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			Name:     scanSetting.Name,
			Kind:     "ScanSetting",
			APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}
	if err := f.Client.Create(context.TODO(), &scanSettingBinding, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSettingBinding)

	// Assert the ScanSettingBinding is Suspended
	if err := f.WaitForScanSettingBindingStatus(f.OperatorNamespace, bindingName, compv1alpha1.ScanSettingBindingPhaseSuspended); err != nil {
		t.Fatalf("ScanSettingBinding %s failed to suspend: %v", bindingName, err)
	}

	if err := f.AssertScanSettingBindingConditionIsSuspended(bindingName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}
	if err := f.AssertComplianceSuiteDoesNotExist(bindingName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}

	scanName := "ocp4-cis"
	err := f.AssertScanDoesNotExist(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	// Update the `ScanSetting.suspend` attribute to `False`
	scanSetting.Suspend = false
	if err := f.Client.Update(context.TODO(), &scanSetting); err != nil {
		t.Fatal(err)
	}
	// Assert the scan is performed
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	if err := f.WaitForScanSettingBindingStatus(f.OperatorNamespace, bindingName, compv1alpha1.ScanSettingBindingPhaseReady); err != nil {
		t.Fatal(err)
	}
	if err := f.AssertCronJobIsNotSuspended(compsuitectrl.GetRerunnerName(bindingName)); err != nil {
		t.Fatal(err)
	}
	if err := f.AssertScanSettingBindingConditionIsReady(bindingName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
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

	if err = f.WaitForProfileDeprecatedWarning(t, scanName, fmt.Sprintf("%s-cis-1-4", pbName)); err != nil {
		t.Fatal(err)
	}

	if err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone); err != nil {
		t.Fatal(err)
	}
}

func TestScanTailoredProfileExtendsDeprecated(t *testing.T) {
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

	tpName := "test-tailored-profile-extends-deprecated"
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Extends:     "ocp4-cis-1-4",
			Title:       "TestScanTailoredProfileExtendsDeprecated",
			Description: "TestScanTailoredProfileExtendsDeprecated",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-cluster-version-operator-exists",
					Rationale: "Test tailored profile extends deprecated",
				},
			},
		},
	}
	createTPErr := f.Client.Create(context.TODO(), tp, nil)
	if createTPErr != nil {
		t.Fatal(createTPErr)
	}
	defer f.Client.Delete(context.TODO(), tp)

	suiteName := framework.GetObjNameFromTest(t)
	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
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
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// When using SSB with TailoredProfile, the scan has same name as the TP
	scanName := tpName
	if err = f.WaitForProfileDeprecatedWarning(t, scanName, tpName); err != nil {
		t.Fatal(err)
	}

	if err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone); err != nil {
		t.Fatal(err)
	}
}

func TestRemediationNeedsReview(t *testing.T) {
	f := framework.Global

	suiteName := framework.GetObjNameFromTest(t)
	scanName := suiteName
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}
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
						ContentImage: "quay.io/openshifttest/co_content:qe_remediation_variable",
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Rule:         "xccdf_org.ssgproject.content_rule_chronyd_or_ntpd_specify_multiple_servers",
						Content:      framework.RhcosContentFile,
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
						},
					},
					Name: scanName,
				},
			},
		},
	}
	// Create the suite
	err := f.Client.Create(context.TODO(), suite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), suite)

	if err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	// Check remediation applicationState is NeedsReview
	remName := scanName + "-chronyd-or-ntpd-specify-multiple-servers"
	err = f.WaitForRemediationState(remName, f.OperatorNamespace, compv1alpha1.RemediationNeedsReview)
	if err != nil {
		t.Fatalf("Failed waiting for remediation to be in NeedsReview state: %v", err)
	}

	// Check remediation annotations
	rem := &compv1alpha1.ComplianceRemediation{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: remName, Namespace: f.OperatorNamespace}, rem)
	if err != nil {
		t.Fatalf("Failed to get remediation %s: %v", remName, err)
	}

	unsetValue, hasUnsetValue := rem.Annotations[compv1alpha1.RemediationUnsetValueAnnotation]
	if !hasUnsetValue || !strings.Contains(unsetValue, "var-multiple-time-servers") {
		t.Fatalf("Expected remediation to have annotation %s containing 'var-multiple-time-servers', got: %v", compv1alpha1.RemediationUnsetValueAnnotation, unsetValue)
	}

	valueRequired, hasValueRequired := rem.Annotations[compv1alpha1.RemediationValueRequiredAnnotation]
	if !hasValueRequired || !strings.Contains(valueRequired, "var-multiple-time-servers") {
		t.Fatalf("Expected remediation to have annotation %s containing 'var-multiple-time-servers', got: %v", compv1alpha1.RemediationValueRequiredAnnotation, valueRequired)
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
//							},
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
