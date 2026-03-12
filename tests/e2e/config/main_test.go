package config_e2e

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	compsuitectrl "github.com/ComplianceAsCode/compliance-operator/pkg/controller/compliancesuite"
	configv1 "github.com/openshift/api/config/v1"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	corev1 "k8s.io/api/core/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
func TestScanStorageOutOfLimitRangeFails(t *testing.T) {
	t.Parallel()
	f := framework.Global
	// Create LimitRange
	lr := &corev1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pvc-limitrange",
			Namespace: f.OperatorNamespace,
		},
		Spec: corev1.LimitRangeSpec{
			Limits: []corev1.LimitRangeItem{
				{
					Type: corev1.LimitTypePersistentVolumeClaim,
					Max: corev1.ResourceList{
						corev1.ResourceStorage: resource.MustParse("5Gi"),
					},
				},
			},
		},
	}
	if err := f.Client.Create(context.TODO(), lr, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), lr)

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
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testScan)
	f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	err = f.AssertScanIsInError(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

}

func TestScanWithNodeSelectorFiltersCorrectly(t *testing.T) {
	t.Parallel()
	f := framework.Global
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}
	testComplianceScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-filtered-scan",
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			NodeSelector: selectWorkers,
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testComplianceScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testComplianceScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, "test-filtered-scan", compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	nodes, err := f.GetNodesWithSelector(selectWorkers)
	if err != nil {
		t.Fatal(err)
	}
	configmaps, err := f.GetConfigMapsFromScan(testComplianceScan)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertNodeNameIsInTargetAndFactIdentifierInCM(nodes, configmaps)
	if err != nil {
		t.Fatal(err)
	}

	if len(nodes) != len(configmaps) {
		t.Fatalf("The number of reports doesn't match the number of selected nodes: %d reports / %d nodes", len(configmaps), len(nodes))
	}
	err = f.AssertScanIsCompliant("test-filtered-scan", f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScanWithNodeSelectorNoMatches(t *testing.T) {
	t.Parallel()
	f := framework.Global
	scanName := framework.GetObjNameFromTest(t)
	selectNone := map[string]string{
		"node-role.kubernetes.io/no-matches": "",
	}
	testComplianceScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			NodeSelector: selectNone,
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug:             true,
				ShowNotApplicable: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testComplianceScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testComplianceScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanIsNotApplicable(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScheduledSuite(t *testing.T) {
	t.Parallel()
	f := framework.Global
	suiteName := "test-scheduled-suite"

	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}

	testSuite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: false,
				Schedule:              "*/2 * * * *",
			},
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					Name: workerScanName,
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							RawResultStorage: compv1alpha1.RawResultStorageSettings{
								Rotation: 1,
							},
							Debug: true,
						},
					},
				},
			},
		},
	}

	err := f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for one re-scan
	err = f.WaitForReScanStatus(f.OperatorNamespace, workerScanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for a second one to assert this is running scheduled as expected
	err = f.WaitForReScanStatus(f.OperatorNamespace, workerScanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	// Remove cronjob so it doesn't keep running while other tests are
	// running. Use Patch instead of Update to avoid resource version
	// conflicts with the controller.
	patch := []byte(`{"spec":{"schedule":""}}`)
	if err = f.Client.Patch(context.TODO(), testSuite, client.RawPatch(types.MergePatchType, patch)); err != nil {
		t.Fatal(err)
	}

	rawResultClaimName, err := f.GetRawResultClaimNameFromScan(f.OperatorNamespace, workerScanName)
	if err != nil {
		t.Fatal(err)
	}

	rotationCheckerPod := framework.GetRotationCheckerWorkload(f.OperatorNamespace, rawResultClaimName)
	if err = f.Client.Create(context.TODO(), rotationCheckerPod, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), rotationCheckerPod)

	err = f.AssertResultStorageHasExpectedItemsAfterRotation(1, f.OperatorNamespace, rotationCheckerPod.Name)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScheduledSuitePriorityClass(t *testing.T) {
	t.Parallel()
	f := framework.Global
	suiteName := "test-scheduled-suite-priority-class"
	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}

	priorityClass := &schedulingv1.PriorityClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-compliance-suite-high-priority",
		},
		Value: 100,
	}

	// Ensure that the priority class is created
	err := f.Client.Create(context.TODO(), priorityClass, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), priorityClass)

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
					Name: workerScanName,
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							PriorityClass: "e2e-compliance-suite-high-priority",
							RawResultStorage: compv1alpha1.RawResultStorageSettings{
								Rotation: 1,
							},
							Debug: true,
						},
					},
				},
			},
		},
	}

	err = f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	podList := &corev1.PodList{}
	err = f.Client.List(context.TODO(), podList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels(map[string]string{
		"workload": "scanner",
	}))
	if err != nil {
		t.Fatal(err)
	}
	// check if the scanning pod has properly been created and has priority class set
	for _, pod := range podList.Items {
		if strings.Contains(pod.Name, workerScanName) {
			if err := framework.WaitForPod(framework.CheckPodPriorityClass(f.KubeClient, pod.Name, f.OperatorNamespace, "e2e-compliance-suite-high-priority")); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScheduledSuiteNoStorage(t *testing.T) {
	t.Parallel()
	f := framework.Global
	suiteName := "test-scheduled-suite-no-storage"
	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}

	falseValue := false
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
					Name: workerScanName,
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							RawResultStorage: compv1alpha1.RawResultStorageSettings{
								Enabled: &falseValue,
							},
							Debug: true,
						},
					},
				},
			},
		},
	}

	err := f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	pvcList := &corev1.PersistentVolumeClaimList{}
	err = f.Client.List(context.TODO(), pvcList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels(map[string]string{
		compv1alpha1.ComplianceScanLabel: workerScanName,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(pvcList.Items) > 0 {
		for _, pvc := range pvcList.Items {
			t.Fatalf("Found unexpected PVC %s", pvc.Name)
		}
		t.Fatal("Expected not to find PVC associated with the scan.")
	}

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScheduledSuiteInvalidPriorityClass(t *testing.T) {
	t.Parallel()
	f := framework.Global
	suiteName := "test-scheduled-suite-invalid-priority-class"

	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}

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
					Name: workerScanName,
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							PriorityClass: "priority-invalid",
							RawResultStorage: compv1alpha1.RawResultStorageSettings{
								Rotation: 1,
							},
							Debug: true,
						},
					},
				},
			},
		},
	}

	err := f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	podList := &corev1.PodList{}
	err = f.Client.List(context.TODO(), podList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels(map[string]string{
		"workload": "scanner",
	}))
	if err != nil {
		t.Fatal(err)
	}
	// check if the scanning pod has properly been created and has priority class set
	for _, pod := range podList.Items {
		if strings.Contains(pod.Name, workerScanName) {
			if err := framework.WaitForPod(framework.CheckPodPriorityClass(f.KubeClient, pod.Name, f.OperatorNamespace, "")); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScheduledSuiteUpdate(t *testing.T) {
	t.Parallel()
	f := framework.Global
	suiteName := framework.GetObjNameFromTest(t)
	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}

	initialSchedule := "0 * * * *"
	testSuite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: false,
				Schedule:              initialSchedule,
			},
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					Name: workerScanName,
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
						},
					},
				},
			},
		},
	}

	err := f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}

	err = f.WaitForCronJobWithSchedule(f.OperatorNamespace, suiteName, initialSchedule)
	if err != nil {
		t.Fatal(err)
	}

	// Get new reference of suite
	foundSuite := &compv1alpha1.ComplianceSuite{}
	key := types.NamespacedName{Name: testSuite.Name, Namespace: testSuite.Namespace}
	if err = f.Client.Get(context.TODO(), key, foundSuite); err != nil {
		t.Fatal(err)
	}

	// Update schedule
	testSuiteCopy := foundSuite.DeepCopy()
	updatedSchedule := "*/2 * * * *"
	testSuiteCopy.Spec.Schedule = updatedSchedule
	if err = f.Client.Update(context.TODO(), testSuiteCopy); err != nil {
		t.Fatal(err)
	}

	if err = f.WaitForCronJobWithSchedule(f.OperatorNamespace, suiteName, updatedSchedule); err != nil {
		t.Fatal(err)
	}

	// Clean up
	// Get new reference of suite
	foundSuite = &compv1alpha1.ComplianceSuite{}
	if err = f.Client.Get(context.TODO(), key, foundSuite); err != nil {
		t.Fatal(err)
	}

	// Remove cronjob so it doesn't keep running while other tests are running
	testSuiteCopy = foundSuite.DeepCopy()
	updatedSchedule = ""
	testSuiteCopy.Spec.Schedule = updatedSchedule
	if err = f.Client.Update(context.TODO(), testSuiteCopy); err != nil {
		t.Fatal(err)
	}
}

func TestScanSettingBindingNoStorage(t *testing.T) {
	t.Parallel()
	f := framework.Global
	objName := framework.GetObjNameFromTest(t)
	var baselineImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "kubeletconfig")
	const requiredRule = "kubelet-eviction-thresholds-set-soft-imagefs-available"
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
	err, found := framework.Global.DoesRuleExist(f.OperatorNamespace, requiredRuleName)
	if err != nil {
		t.Fatal(err)
	} else if !found {
		t.Fatalf("Expected rule %s not found", requiredRuleName)
	}

	suiteName := "storage-test-node"
	scanSettingBindingName := suiteName

	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
			Annotations: map[string]string{
				compv1alpha1.DisableOutdatedReferenceValidation: "true",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "storage-test",
			Description: "A test tailored profile to test storage settings",
			ManualRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      prefixName(pbName, requiredRule),
					Rationale: "To be tested",
				},
			},
		},
	}

	createTPErr := f.Client.Create(context.TODO(), tp, nil)
	if createTPErr != nil {
		t.Fatal(createTPErr)
	}
	defer f.Client.Delete(context.TODO(), tp)
	scanSettingNoStorageName := objName + "-setting-no-storage"
	falseValue := false
	trueValue := true
	scanSettingWithStorageName := objName + "-setting-with-storage"
	scanSettingNoStorage := compv1alpha1.ScanSetting{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingNoStorageName,
			Namespace: f.OperatorNamespace,
		},
		ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
			AutoApplyRemediations: false,
		},
		ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
			Debug: true,
			RawResultStorage: compv1alpha1.RawResultStorageSettings{
				Enabled: &falseValue,
			},
		},
		Roles: []string{"master", "worker"},
	}

	scanSettingWithStorage := compv1alpha1.ScanSetting{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingWithStorageName,
			Namespace: f.OperatorNamespace,
		},
		ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
			AutoApplyRemediations: false,
		},
		ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
			Debug: true,
			RawResultStorage: compv1alpha1.RawResultStorageSettings{
				Enabled: &trueValue,
			},
		},
		Roles: []string{"master", "worker"},
	}

	if err := f.Client.Create(context.TODO(), &scanSettingNoStorage, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSettingNoStorage)

	if err := f.Client.Create(context.TODO(), &scanSettingWithStorage, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSettingWithStorage)

	scanSettingBinding := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingBindingName,
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
			Name:     scanSettingNoStorage.Name,
			Kind:     "ScanSetting",
			APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}

	if err := f.Client.Create(context.TODO(), &scanSettingBinding, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSettingBinding)

	// Wait until the suite finishes, thus verifying the suite exists
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, scanSettingBindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	scanKey := types.NamespacedName{Namespace: f.OperatorNamespace, Name: suiteName + "-master"}
	scan := &compv1alpha1.ComplianceScan{}
	if err := f.Client.Get(context.TODO(), scanKey, scan); err != nil {
		t.Fatal(err)
	}

	if scan.Spec.RawResultStorage.Enabled != nil && *scan.Spec.RawResultStorage.Enabled {
		t.Fatal("Expected that the scan does not have raw result storage enabled")
	}

	pvcList := &corev1.PersistentVolumeClaimList{}
	err = f.Client.List(context.TODO(), pvcList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels(map[string]string{
		compv1alpha1.ComplianceScanLabel: scan.Name,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(pvcList.Items) > 0 {
		for _, pvc := range pvcList.Items {
			t.Fatalf("Found unexpected PVC %s", pvc.Name)
		}
		t.Fatal("Expected not to find PVC associated with the scan.")
	}
	// let's delete the scan setting binding
	if err := f.Client.Delete(context.TODO(), &scanSettingBinding); err != nil {
		t.Fatal(err)
	}

	// let's create a new scan setting binding with the with storage setting
	scanSettingBinding = compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingBindingName,
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
			Name:     scanSettingWithStorage.Name,
			Kind:     "ScanSetting",
			APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}

	if err := f.Client.Create(context.TODO(), &scanSettingBinding, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSettingBinding)

	// Wait until the suite finishes, thus verifying the suite exists
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, scanSettingBindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	scan = &compv1alpha1.ComplianceScan{}
	if err := f.Client.Get(context.TODO(), scanKey, scan); err != nil {
		t.Fatal(err)
	}

	if scan.Spec.RawResultStorage.Enabled != nil && *scan.Spec.RawResultStorage.Enabled == false {
		t.Fatal("Expected that the scan has raw result storage enabled")
	}

	pvcList = &corev1.PersistentVolumeClaimList{}
	err = f.Client.List(context.TODO(), pvcList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels(map[string]string{
		compv1alpha1.ComplianceScanLabel: scan.Name,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(pvcList.Items) == 0 {
		t.Fatal("Expected to find PVC associated with the scan.")
	}
	t.Logf("Found PVC %s", pvcList.Items[0].Name)
	t.Logf("Succeeded to create PVC associated with the scan.")

	// let's update the scan setting binding to use the no storage setting
	ssb := &compv1alpha1.ScanSettingBinding{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: f.OperatorNamespace, Name: scanSettingBindingName}, ssb); err != nil {
		t.Fatal("Expected to find the scan setting binding, but got error: ", err)
	}
	ssb.SettingsRef.Name = scanSettingNoStorage.Name
	if err := f.Client.Update(context.TODO(), ssb); err != nil {
		t.Fatal(err)
	}

	// let's rerun the scan
	err = f.ReRunScan(scan.Name, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
	// wait for scan to finish
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, scanSettingBindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	// get the scan again
	scan = &compv1alpha1.ComplianceScan{}
	if err := f.Client.Get(context.TODO(), scanKey, scan); err != nil {
		t.Fatal(err)
	}

	// make sure enabled is false
	if scan.Spec.RawResultStorage.Enabled != nil && *scan.Spec.RawResultStorage.Enabled == true {
		t.Fatal("Expected that the scan does not have raw result storage enabled")
	}

	// let's check that the PVC should be there and still associated with the scan
	pvcList = &corev1.PersistentVolumeClaimList{}
	err = f.Client.List(context.TODO(), pvcList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels(map[string]string{
		compv1alpha1.ComplianceScanLabel: scan.Name,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(pvcList.Items) == 0 {
		t.Fatal("Expected to find PVC associated with the scan.")
	}
	t.Logf("Found PVC %s", pvcList.Items[0].Name)
	t.Logf("Succeeded to check that the PVC is still there.")

}

func TestScheduledSuiteTimeoutFail(t *testing.T) {
	t.Parallel()
	f := framework.Global
	suiteName := "test-scheduled-suite-timeout-fail"

	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}

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
					Name: workerScanName,
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							MaxRetryOnTimeout: 0,
							RawResultStorage: compv1alpha1.RawResultStorageSettings{
								Rotation: 1,
							},
							Timeout: "1s",
							Debug:   true,
						},
					},
				},
			},
		},
	}

	err := f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultError)
	if err != nil {
		t.Fatal(err)
	}
	scan := &compv1alpha1.ComplianceScan{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: workerScanName, Namespace: f.OperatorNamespace}, scan)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := scan.Annotations[compv1alpha1.ComplianceScanTimeoutAnnotation]; !ok {
		t.Fatal("The scan should have the timeout annotation")
	}
}

func TestScanWithCustomStorageClass(t *testing.T) {
	t.Parallel()
	f := framework.Global

	scanName := framework.GetObjNameFromTest(t)
	suiteName := scanName + "-suite"
	storageClassName := scanName + "-gold"

	// Get the default storage class provisioner for our custom storage class
	defaultProvisioner, err := f.GetDefaultStorageClassProvisioner()
	if err != nil {
		t.Skipf("skipping test: no default storage class provisioner available: %s", err)
	}

	// Create custom StorageClass named "gold"
	customStorageClass, err := f.CreateCustomStorageClass(storageClassName, defaultProvisioner)
	if err != nil {
		t.Fatalf("failed to create custom storage class object %s: %s", storageClassName, err)
	}
	err = f.Client.Create(context.TODO(), customStorageClass, nil)
	if err != nil {
		t.Fatalf("failed to create custom storage class %s: %s", storageClassName, err)
	}
	defer f.Client.Delete(context.TODO(), customStorageClass)

	// Create ComplianceSuite with custom storage configuration
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
					Name: scanName,
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ScanType:     compv1alpha1.ScanTypeNode,
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
						NodeSelector: map[string]string{
							"node-role.kubernetes.io/worker": "",
						},
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
							RawResultStorage: compv1alpha1.RawResultStorageSettings{
								StorageClassName: &storageClassName,
								PVAccessModes: []corev1.PersistentVolumeAccessMode{
									corev1.ReadWriteOnce,
								},
							},
						},
					},
				},
			},
		},
	}

	err = f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatalf("failed to create compliance suite: %s", err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	// Wait for the scan to complete
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatalf("scan did not complete successfully: %s", err)
	}

	// Verify PVC has correct storageClassName and accessModes
	err = f.AssertScanPVCHasStorageConfig(scanName, f.OperatorNamespace, storageClassName, corev1.ReadWriteOnce)
	if err != nil {
		t.Fatalf("PVC verification failed: %s", err)
	}

	t.Logf("Successfully verified scan %s has custom storage configuration", scanName)
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

	// Create a second ScanSettingBinding with ocp4-pci-dss profile using the same ScanSetting
	bindingName2 := framework.GetObjNameFromTest(t) + "-binding-pci"
	scanSettingBinding2 := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName2,
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
			Name:     scanSetting.Name,
			Kind:     "ScanSetting",
			APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}
	if err := f.Client.Create(context.TODO(), &scanSettingBinding2, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSettingBinding2)

	// Wait until the first scan completes since the CronJob is created
	// after the scan is done
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName2, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	suite := &compv1alpha1.ComplianceSuite{}
	key := types.NamespacedName{Name: bindingName, Namespace: f.OperatorNamespace}
	if err := f.Client.Get(context.TODO(), key, suite); err != nil {
		t.Fatal(err)
	}

	suite2 := &compv1alpha1.ComplianceSuite{}
	key2 := types.NamespacedName{Name: bindingName2, Namespace: f.OperatorNamespace}
	if err := f.Client.Get(context.TODO(), key2, suite2); err != nil {
		t.Fatal(err)
	}

	// Assert the CronJob is not suspended.
	if err := f.AssertCronJobIsNotSuspended(compsuitectrl.GetRerunnerName(suite.Name)); err != nil {
		t.Fatal(err)
	}
	if err := f.AssertCronJobIsNotSuspended(compsuitectrl.GetRerunnerName(suite2.Name)); err != nil {
		t.Fatal(err)
	}
	if err := f.AssertScanSettingBindingConditionIsReady(bindingName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}
	if err := f.AssertScanSettingBindingConditionIsReady(bindingName2, f.OperatorNamespace); err != nil {
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
	if err := f.WaitForScanSettingBindingStatus(f.OperatorNamespace, bindingName2, compv1alpha1.ScanSettingBindingPhaseSuspended); err != nil {
		t.Fatalf("ScanSettingBinding %s failed to suspend", bindingName2)
	}
	if err := f.AssertCronJobIsSuspended(compsuitectrl.GetRerunnerName(suite.Name)); err != nil {
		t.Fatal(err)
	}
	if err := f.AssertCronJobIsSuspended(compsuitectrl.GetRerunnerName(suite2.Name)); err != nil {
		t.Fatal(err)
	}
	if err := f.AssertScanSettingBindingConditionIsSuspended(bindingName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}
	if err := f.AssertScanSettingBindingConditionIsSuspended(bindingName2, f.OperatorNamespace); err != nil {
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
	if err := f.WaitForScanSettingBindingStatus(f.OperatorNamespace, bindingName2, compv1alpha1.ScanSettingBindingPhaseReady); err != nil {
		t.Fatalf("ScanSettingBinding %s failed to resume", bindingName2)
	}
	if err := f.AssertCronJobIsNotSuspended(compsuitectrl.GetRerunnerName(suite.Name)); err != nil {
		t.Fatal(err)
	}
	if err := f.AssertCronJobIsNotSuspended(compsuitectrl.GetRerunnerName(suite2.Name)); err != nil {
		t.Fatal(err)
	}
	if err := f.AssertScanSettingBindingConditionIsReady(bindingName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}
	if err := f.AssertScanSettingBindingConditionIsReady(bindingName2, f.OperatorNamespace); err != nil {
		t.Fatal(err)
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

func TestScannerAndAPICollectorLimitsConfigurable(t *testing.T) {
	f := framework.Global

	// Create ScanSetting with resource limits
	scanSettingName := framework.GetObjNameFromTest(t) + "-scansetting"
	cpuLimit := "150m"
	memoryLimit := "512Mi"
	scanSetting := compv1alpha1.ScanSetting{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingName,
			Namespace: f.OperatorNamespace,
		},
		ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
			AutoApplyRemediations: false,
			Schedule:              "0 1 * * *",
		},
		ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
			Debug: true,
			ScanLimits: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceCPU:    resource.MustParse(cpuLimit),
				corev1.ResourceMemory: resource.MustParse(memoryLimit),
			},
		},
		Roles: []string{"master", "worker"},
	}
	if err := f.Client.Create(context.TODO(), &scanSetting, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSetting)

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
				Name:     "ocp4-cis-node",
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
	defer func() {
		if err := f.DeleteScanSettingBindingAndWaitForCleanup(&scanSettingBinding); err != nil {
			t.Logf("cleanup ScanSettingBinding %s: %v", bindingName, err)
		}
	}()

	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	// Get the ComplianceSuite to verify scanLimits
	suite := &compv1alpha1.ComplianceSuite{}
	key := types.NamespacedName{Name: bindingName, Namespace: f.OperatorNamespace}
	if err := f.Client.Get(context.TODO(), key, suite); err != nil {
		t.Fatal(err)
	}

	for _, scanWrapper := range suite.Spec.Scans {
		if scanWrapper.ScanLimits == nil {
			t.Fatalf("scan %s in ComplianceSuite %s has no scanLimits", scanWrapper.Name, bindingName)
		}

		cpuQty, hasCPU := scanWrapper.ScanLimits[corev1.ResourceCPU]
		if !hasCPU {
			t.Fatalf("scan %s in ComplianceSuite %s has no CPU limit", scanWrapper.Name, bindingName)
		}
		if cpuQty.String() != cpuLimit {
			t.Fatalf("scan %s in ComplianceSuite %s has CPU limit %s, expected %s", scanWrapper.Name, bindingName, cpuQty.String(), cpuLimit)
		}

		memQty, hasMem := scanWrapper.ScanLimits[corev1.ResourceMemory]
		if !hasMem {
			t.Fatalf("scan %s in ComplianceSuite %s has no memory limit", scanWrapper.Name, bindingName)
		}
		if memQty.String() != memoryLimit {
			t.Fatalf("scan %s in ComplianceSuite %s has memory limit %s, expected %s", scanWrapper.Name, bindingName, memQty.String(), memoryLimit)
		}
	}

	// Wait for scanner pods to be created and verify their resource limits
	var podList *corev1.PodList
	err := wait.Poll(framework.RetryInterval, framework.Timeout, func() (bool, error) {
		podList = &corev1.PodList{}
		listErr := f.Client.List(context.TODO(), podList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels(map[string]string{
			"workload": "scanner",
		}))
		if listErr != nil {
			return false, listErr
		}
		if len(podList.Items) == 0 {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("failed to find scanner pods: %v", err)
	}

	if len(podList.Items) == 0 {
		t.Fatal("unable to verify pod limits")
	}

	// Verify resource limits for all scanner pods
	for _, pod := range podList.Items {
		// Wait for pod limits to be set correctly
		if err := framework.WaitForPod(framework.CheckPodLimit(f.KubeClient, pod.Name, f.OperatorNamespace, cpuLimit, memoryLimit)); err != nil {
			t.Fatalf("pod %s does not have expected resource limits: %v", pod.Name, err)
		}
	}
}

func TestStrictNodeScanConfiguration(t *testing.T) {
	f := framework.Global
	// Get one worker node
	workerNodes, err := f.GetNodesWithSelector(map[string]string{
		"node-role.kubernetes.io/worker": "",
	})
	if err != nil {
		t.Fatal(err)
	}
	nodeName := workerNodes[0].Name

	// Cordon the node (mark as unschedulable)
	node := &corev1.Node{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: nodeName}, node); err != nil {
		t.Fatalf("failed to get node %s: %s", nodeName, err)
	}
	nodeCopy := node.DeepCopy()
	nodeCopy.Spec.Unschedulable = true
	if err := f.Client.Update(context.TODO(), nodeCopy); err != nil {
		t.Fatalf("failed to cordon node %s: %s", nodeName, err)
	}
	defer func() {
		// Uncordon the node - get fresh copy to avoid conflict errors
		uncordonNode := &corev1.Node{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: nodeName}, uncordonNode); err != nil {
			t.Log(err)
			return
		}
		uncordonNode.Spec.Unschedulable = false
		if err := f.Client.Update(context.TODO(), uncordonNode); err != nil {
			t.Log(err)
		}
	}()

	// Verify node is unschedulable
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: nodeName}, node); err != nil {
		t.Fatalf("failed to get node %s: %s", nodeName, err)
	}
	if !node.Spec.Unschedulable {
		t.Fatalf("node %s is not marked as unschedulable", nodeName)
	}

	// Create ScanSetting with strictNodeScan: false
	scanSettingName := framework.GetObjNameFromTest(t) + "-strict"
	strictFalse := false
	scanSetting := compv1alpha1.ScanSetting{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingName,
			Namespace: f.OperatorNamespace,
		},
		ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
			AutoApplyRemediations: false,
		},
		ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
			StrictNodeScan: &strictFalse,
			Debug:          false,
		},
		Roles: []string{"worker"},
	}
	if err := f.Client.Create(context.TODO(), &scanSetting, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSetting)

	// Create ScanSettingBinding
	bindingName := framework.GetObjNameFromTest(t) + "-binding"
	scanSettingBinding := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     "rhcos4-e8",
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

	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err) 
	}
    
	if err := f.Client.Delete(context.TODO(), &scanSettingBinding); err != nil {
		t.Fatal(err)
	}

	if err := f.WaitForScanCleanup(); err != nil {
		t.Fatalf("timed out waiting for ComplianceScans to be deleted: %s", err)
	}
	// Patch ScanSetting to set strictNodeScan: true
	strictTrue := true
	scanSettingUpdate := &compv1alpha1.ScanSetting{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: scanSettingName, Namespace: f.OperatorNamespace}, scanSettingUpdate); err != nil {
		t.Fatal(err)
	}
	scanSettingUpdate.StrictNodeScan = &strictTrue
	if err := f.Client.Update(context.TODO(), scanSettingUpdate); err != nil {
		t.Fatalf("failed to update ScanSetting: %s", err)
	}
	
	// Clear metadata to ensure clean recreation of the ssb
	scanSettingBinding.ObjectMeta = metav1.ObjectMeta{
		Name:      bindingName,
		Namespace: f.OperatorNamespace,
	}
	if err := f.Client.Create(context.TODO(), &scanSettingBinding, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSettingBinding)

	suite := &compv1alpha1.ComplianceSuite{}
	suiteKey := types.NamespacedName{Name: bindingName, Namespace: f.OperatorNamespace}
	if err := wait.PollImmediate(framework.RetryInterval, framework.Timeout, func() (bool, error) {
		err := f.Client.Get(context.TODO(), suiteKey, suite)
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	}); err != nil {
		t.Fatalf("timed out waiting for ComplianceSuite %s to be created: %v", bindingName, err)
	}

	// With strictNodeScan: true and an unschedulable node, the suite should remain PENDING for 30 seconds
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if err := f.Client.Get(context.TODO(), suiteKey, suite); err != nil {
			t.Fatalf("failed to get ComplianceSuite %s: %v", bindingName, err)
		}
		if suite.Status.Phase != compv1alpha1.PhasePending {
			t.Fatalf("suite left PENDING state (expected to remain PENDING for 30s): phase=%s", suite.Status.Phase)
		}
		time.Sleep(framework.RetryInterval)
}
}

