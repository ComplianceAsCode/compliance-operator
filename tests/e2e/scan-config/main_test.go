package scan_config_e2e

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	compsuitectrl "github.com/ComplianceAsCode/compliance-operator/pkg/controller/compliancesuite"
	configv1 "github.com/openshift/api/config/v1"
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

	// Ensure that all the scans in the suite have finished and are marked as Done.
	// Accept any result since this test validates storage behavior, not compliance outcome.
	err = f.WaitForSuiteScansStatusAnyResult(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone,
		compv1alpha1.ResultCompliant, compv1alpha1.ResultNonCompliant, compv1alpha1.ResultError)
	if err != nil {
		t.Fatal(err)
	}

	pvcList := &corev1.PersistentVolumeClaimList{}
	err = f.Client.List(context.TODO(), pvcList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels(map[string]string{
		compv1alpha1.ComplianceScanLabel: workerScanName,
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, pvc := range pvcList.Items {
		t.Fatalf("Found unexpected PVC %s", pvc.Name)
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

	// Verify suitererunner resource limits and requests through Jobs
	expectedResourceCpu := "10m"
	expectedResourceMem := "20Mi"
	expectedLimitCpu := "50m"
	expectedLimitMem := "100Mi"
	err = f.AssertSuiteRerunnerResourcesInJobs(f.OperatorNamespace, suiteName, expectedLimitCpu, expectedLimitMem, expectedResourceCpu, expectedResourceMem)
	if err != nil {
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
	workerScanWithRetryName := fmt.Sprintf("%s-workers-scan-retry", suiteName)
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
				{
					Name: workerScanWithRetryName,
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							MaxRetryOnTimeout: 1,
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

	// Test point 1: Verify timeout behavior without retry (MaxRetryOnTimeout: 0)
	scan := &compv1alpha1.ComplianceScan{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: workerScanName, Namespace: f.OperatorNamespace}, scan)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := scan.Annotations[compv1alpha1.ComplianceScanTimeoutAnnotation]; !ok {
		t.Fatal("The scan should have the timeout annotation")
	}

	// Test point 2: Verify timeout behavior with retry (MaxRetryOnTimeout: 1)
	scanWithRetry := &compv1alpha1.ComplianceScan{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: workerScanWithRetryName, Namespace: f.OperatorNamespace}, scanWithRetry)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := scanWithRetry.Annotations[compv1alpha1.ComplianceScanTimeoutAnnotation]; !ok {
		t.Fatal("The scan with retry should have the timeout annotation")
	}
	// Verify that the retry mechanism worked: CurrentIndex should be 1 (initial + 1 retry)
	if scanWithRetry.Status.CurrentIndex != 1 {
		t.Fatalf("Expected CurrentIndex to be 1 (initial scan + 1 retry), got %d", scanWithRetry.Status.CurrentIndex)
	}
	// Verify error message indicates timeout
	if !strings.Contains(scanWithRetry.Status.ErrorMessage, "Timeout") && !strings.Contains(scanWithRetry.Status.ErrorMessage, "timeout") {
		t.Fatalf("Expected error message to contain 'Timeout', got: %s", scanWithRetry.Status.ErrorMessage)
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

	// Test Phase 1: Automatic toleration injection (without explicit tolerations)
	// This verifies that the Compliance Operator automatically adds tolerations
	// to scan pods, allowing them to run on tainted nodes without user configuration.
	suiteNameAuto := framework.GetObjNameFromTest(t) + "-auto"
	scanNameAuto := suiteNameAuto
	suiteAuto := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteNameAuto,
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
							//No ScanTolerations specified - testing automatic injection
						},
					},
					Name: scanNameAuto,
				},
			},
		},
	}
	if err := f.Client.Create(context.TODO(), suiteAuto, nil); err != nil {
		t.Fatalf("failed to create suite %s: %s", suiteNameAuto, err)
	}
	defer f.Client.Delete(context.TODO(), suiteAuto)

	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteNameAuto, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatalf("automatic toleration test failed: %s", err)
	}

	// Verify that all scanner pods have the expected tolerations (Phase 1 - automatic)
	podsAuto, err := f.GetPodsForScan(scanNameAuto)
	if err != nil {
		t.Fatalf("failed to get pods: %s", err)
	}
	framework.AssertAllScannerPodsHaveToleration(t, podsAuto, func(tol corev1.Toleration) bool {
		return (tol.Key == "" && tol.Operator == corev1.TolerationOpExists) ||
			(tol.Key == taintKey && tol.Effect == corev1.TaintEffectNoSchedule)
	}, fmt.Sprintf("expected wildcard or specific toleration for taint key %s", taintKey))

	// Test Phase 2: Explicit toleration configuration
	// This verifies that user-provided tolerations are respected and work correctly.
	suiteName := framework.GetObjNameFromTest(t) + "-explicit"
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
		t.Fatalf("explicit toleration test failed: %s", err)
	}

	// Verify that all scanner pods have the expected tolerations (Phase 2 - explicit)
	podsExplicit, err := f.GetPodsForScan(scanName)
	if err != nil {
		t.Fatalf("failed to get pods: %s", err)
	}
	framework.AssertAllScannerPodsHaveToleration(t, podsExplicit, func(tol corev1.Toleration) bool {
		return tol.Key == taintKey && tol.Effect == corev1.TaintEffectNoSchedule
	}, fmt.Sprintf("expected toleration for taint key %s (explicit configuration)", taintKey))
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

	// Wait for the old ComplianceSuite to be fully garbage collected.
	// WaitForScanCleanup only waits for ComplianceScan objects; the
	// owning ComplianceSuite may still exist briefly. If we recreate
	// the ScanSettingBinding before the old suite is gone, the
	// PollImmediate below can observe the old suite's Phase=DONE
	// instead of the new suite's empty Phase, causing a false failure.
	if err := wait.PollImmediate(framework.RetryInterval, framework.Timeout, func() (bool, error) {
		var oldSuite compv1alpha1.ComplianceSuite
		err := f.Client.Get(context.TODO(), types.NamespacedName{Name: bindingName, Namespace: f.OperatorNamespace}, &oldSuite)
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		log.Printf("ComplianceSuite %s still exists, waiting for garbage collection", bindingName)
		return false, nil
	}); err != nil {
		t.Fatalf("timed out waiting for old ComplianceSuite %s to be deleted: %v", bindingName, err)
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
	// Wait for the suite controller to set a phase: a suite it hasn't
	// reconciled yet has none.
	if err := wait.PollImmediate(framework.RetryInterval, framework.Timeout, func() (bool, error) {
		err := f.Client.Get(context.TODO(), suiteKey, suite)
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return suite.Status.Phase != "", nil
	}); err != nil {
		t.Fatalf("timed out waiting for ComplianceSuite %s to be created and get a phase: %v", bindingName, err)
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

func TestSuiteWithInvalidScheduleShowsError(t *testing.T) {
	t.Parallel()
	f := framework.Global
	suiteName := "test-suite-with-invalid-schedule"
	testSuite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: false,
				Schedule:              "This is WRONG",
			},
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					Name: fmt.Sprintf("%s-workers-scan", suiteName),
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
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
	err := f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultError)
	if err != nil {
		t.Fatal(err)
	}
	err = f.SuiteErrorMessageMatchesRegex(f.OperatorNamespace, suiteName, "Suite was invalid: .*")
	if err != nil {
		t.Fatal(err)
	}
}

func TestScheduledSuitePlatformNoStorage(t *testing.T) {
	t.Parallel()
	f := framework.Global
	// The scan expects the cluster OAuth to have no htpasswd identity
	// provider, which TestPlatformAndNodeSuiteScan adds for a while.
	f.HoldScanLocks(t, "cluster-oauth")
	suiteName := "test-scheduled-suite-platform-no-storage"
	platformScanName := fmt.Sprintf("%s-platform-scan", suiteName)

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
					Name: platformScanName,
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.OcpContentFile,
						Rule:         "xccdf_org.ssgproject.content_rule_ocp_idp_no_htpasswd",
						ScanType:     compv1alpha1.ScanTypePlatform,
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

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}

	pvcList := &corev1.PersistentVolumeClaimList{}
	err = f.Client.List(context.TODO(), pvcList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels(map[string]string{
		compv1alpha1.ComplianceScanLabel: platformScanName,
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, pvc := range pvcList.Items {
		t.Fatalf("Found unexpected PVC %s", pvc.Name)
	}
}

// Verifies that setting timeout to "0s" disables the timeout functionality
func TestTimeoutDisabledWithZeroValue(t *testing.T) {
	t.Parallel()
	f := framework.Global

	// Create a new ScanSetting with timeout set to 0s (disabled)
	scanSettingName := framework.GetObjNameFromTest(t) + "-scansetting"
	scanSetting := compv1alpha1.ScanSetting{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingName,
			Namespace: f.OperatorNamespace,
		},
		ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
			AutoApplyRemediations: false,
		},
		ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
			Timeout: "0s",
		},
		Roles: []string{"master", "worker"},
	}
	if err := f.Client.Create(context.TODO(), &scanSetting, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSetting)

	// Bind the ScanSetting to a Profile
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

	// Wait for the scan to complete successfully
	// With timeout set to 0s, the scan should not timeout and complete normally
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	// Verify that scans do not have the timeout annotation
	suite := &compv1alpha1.ComplianceSuite{}
	key := types.NamespacedName{Name: bindingName, Namespace: f.OperatorNamespace}
	if err := f.Client.Get(context.TODO(), key, suite); err != nil {
		t.Fatal(err)
	}

	for _, scanStatus := range suite.Status.ScanStatuses {
		// Verify the scan does not have the timeout annotation
		scan := &compv1alpha1.ComplianceScan{}
		scanKey := types.NamespacedName{Name: scanStatus.Name, Namespace: f.OperatorNamespace}
		if err := f.Client.Get(context.TODO(), scanKey, scan); err != nil {
			t.Fatalf("failed to get scan %s: %s", scanStatus.Name, err)
		}
		if _, hasTimeout := scan.Annotations[compv1alpha1.ComplianceScanTimeoutAnnotation]; hasTimeout {
			t.Fatalf("scan %s should not have timeout annotation when timeout is disabled (0s), but it does", scanStatus.Name)
		}
	}
}

func TestScanSettingBinding(t *testing.T) {
	t.Parallel()
	f := framework.Global
	objName := framework.GetObjNameFromTest(t)
	const defaultCpuLimit = "100m"
	const testMemoryLimit = "432Mi"

	rhcosPb := &compv1alpha1.ProfileBundle{}
	err := f.Client.Get(context.TODO(), types.NamespacedName{Name: "rhcos4", Namespace: f.OperatorNamespace}, rhcosPb)
	if err != nil {
		t.Fatalf("unable to get rhcos4 profile bundle required for test: %s", err)
	}

	rhcos4e8profile := &compv1alpha1.Profile{}
	key := types.NamespacedName{Namespace: f.OperatorNamespace, Name: rhcosPb.Name + "-e8"}
	if err := f.Client.Get(context.TODO(), key, rhcos4e8profile); err != nil {
		t.Fatal(err)
	}

	rhcos4moderateprofile := &compv1alpha1.Profile{}
	moderateKey := types.NamespacedName{Namespace: f.OperatorNamespace, Name: rhcosPb.Name + "-moderate"}
	if err := f.Client.Get(context.TODO(), moderateKey, rhcos4moderateprofile); err != nil {
		t.Fatal(err)
	}

	scanSettingName := objName + "-setting"
	scanSetting := compv1alpha1.ScanSetting{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingName,
			Namespace: f.OperatorNamespace,
		},
		ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
			AutoApplyRemediations: false,
		},
		ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
			Debug: true,
			ScanLimits: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceMemory: resource.MustParse(testMemoryLimit),
			},
		},
		Roles: []string{"master", "worker"},
	}

	if err := f.Client.Create(context.TODO(), &scanSetting, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSetting)

	scanSettingBindingName := "generated-suite"
	scanSettingBinding := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingBindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			// TODO: test also OCP profile when it works completely
			{
				Name:     rhcos4e8profile.Name,
				Kind:     "Profile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
			{
				Name:     rhcos4moderateprofile.Name,
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

	// Wait until the suite finishes, thus verifying the suite exists
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, scanSettingBindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	masterScanKey := types.NamespacedName{Namespace: f.OperatorNamespace, Name: rhcos4e8profile.Name + "-master"}
	masterScan := &compv1alpha1.ComplianceScan{}
	if err := f.Client.Get(context.TODO(), masterScanKey, masterScan); err != nil {
		t.Fatal(err)
	}

	if masterScan.Spec.Debug != true {
		t.Fatal("Expected that the settings set debug to true in master scan")
	}

	workerScanKey := types.NamespacedName{Namespace: f.OperatorNamespace, Name: rhcos4e8profile.Name + "-worker"}
	workerScan := &compv1alpha1.ComplianceScan{}
	if err := f.Client.Get(context.TODO(), workerScanKey, workerScan); err != nil {
		t.Fatal(err)
	}

	if workerScan.Spec.Debug != true {
		t.Fatal("Expected that the settings set debug to true in workers scan")
	}

	moderateMasterScanKey := types.NamespacedName{Namespace: f.OperatorNamespace, Name: rhcos4moderateprofile.Name + "-master"}
	moderateMasterScan := &compv1alpha1.ComplianceScan{}
	if err := f.Client.Get(context.TODO(), moderateMasterScanKey, moderateMasterScan); err != nil {
		t.Fatal(err)
	}

	if moderateMasterScan.Spec.Debug != true {
		t.Fatal("Expected that the settings set debug to true in moderate master scan")
	}

	moderateWorkerScanKey := types.NamespacedName{Namespace: f.OperatorNamespace, Name: rhcos4moderateprofile.Name + "-worker"}
	moderateWorkerScan := &compv1alpha1.ComplianceScan{}
	if err := f.Client.Get(context.TODO(), moderateWorkerScanKey, moderateWorkerScan); err != nil {
		t.Fatal(err)
	}

	if moderateWorkerScan.Spec.Debug != true {
		t.Fatal("Expected that the settings set debug to true in moderate worker scan")
	}

	podList := &corev1.PodList{}
	if err := f.Client.List(context.TODO(), podList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels(map[string]string{
		"workload": "scanner",
	})); err != nil {
		t.Fatal(err)
	}
	// check if the scanning pod has properly been created and has limits set
	for _, pod := range podList.Items {
		if strings.Contains(pod.Name, masterScan.Name) || strings.Contains(pod.Name, workerScan.Name) ||
			strings.Contains(pod.Name, moderateMasterScan.Name) || strings.Contains(pod.Name, moderateWorkerScan.Name) {
			if err := framework.WaitForPod(framework.CheckPodLimit(f.KubeClient, pod.Name, f.OperatorNamespace, defaultCpuLimit, testMemoryLimit)); err != nil {
				t.Fatal(err)
			}
		}
	}

}

func TestScanSettingBindingUsesDefaultScanSetting(t *testing.T) {
	t.Parallel()
	f := framework.Global
	objName := framework.GetObjNameFromTest(t)
	scanSettingBindingName := objName + "-binding"
	scanSettingBinding := compv1alpha1.ScanSettingBinding{
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
		},
	}
	if err := f.Client.Create(context.TODO(), &scanSettingBinding, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSettingBinding)

	// Wait until the suite finishes
	err := f.WaitForSuiteScansStatus(f.OperatorNamespace, scanSettingBindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	bindingKey := types.NamespacedName{Namespace: f.OperatorNamespace, Name: scanSettingBindingName}
	binding := &compv1alpha1.ScanSettingBinding{}
	if err := f.Client.Get(context.TODO(), bindingKey, binding); err != nil {
		t.Fatal(err)
	}

	// Make sure the binding used the `default` ScanSetting.
	if binding.SettingsRef.Name != "default" {
		t.Fatal("Expected the settings reference to use the default ScanSetting")
	}
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

func TestScanWithUnexistentResourceFails(t *testing.T) {
	// This tests scan behavior when Kubernetes resource doesn't exist
	// The data stream, content image and profile all exist
	t.Parallel()
	f := framework.Global
	pbName := framework.GetObjNameFromTest(t)
	var unexistentImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "unexistent_resource")
	origPb, err := f.CreateProfileBundle(pbName, unexistentImage, framework.UnexistentResourceContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle: %s", err)
	}
	// This should get cleaned up at the end of the test
	defer f.Client.Delete(context.TODO(), origPb)
	if err = f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("failed waiting for the ProfileBundle to become available: %s", err)
	}

	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_test",
			Content:      framework.UnexistentResourceContentFile,
			ContentImage: unexistentImage,
			Rule:         "xccdf_org.ssgproject.content_rule_api_server_unexistent_resource",
			ScanType:     compv1alpha1.ScanTypePlatform,
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err = f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertScanIsNonCompliant(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	if err = f.ScanHasWarnings(scanName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}

	// Validate exit-code is "2"
	exitCode, _, err := f.GetScanExitCodeAndErrorMsg(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
	expectedExitCode := "2"
	if exitCode != expectedExitCode {
		t.Fatalf("Expected ConfigMap exit-code to be '%s', but got: '%s'", expectedExitCode, exitCode)
	}
}

func TestScanWithInvalidScanTypeFails(t *testing.T) {
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
			Content:      "ssg-ocp4-non-existent.xml",
			ContentImage: contentImagePath,
			ScanType:     "BadScanType",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
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
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanIsInError(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScanWithInvalidContentFails(t *testing.T) {
	// This test logs a "Could not get Profile" error, but that is expected
	t.Parallel()
	f := framework.Global
	scanName := "test-scan-w-invalid-content"
	exampleComplianceScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      "ssg-ocp4-non-existent.xml",
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

func TestSuiteScan(t *testing.T) {
	t.Parallel()
	f := framework.Global
	suiteName := "test-suite-two-scans"
	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	// Scan the spare workers, not the lane nodes other tests reboot.
	selectWorkers := f.WorkerScanSelector()

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
	f.HoldScanLocks(t, "ocp4-cis", "ocp4-moderate", "ocp4-moderate-node", "rhcos4-moderate")
	bindingName := framework.GetObjNameFromTest(t)
	role := f.WorkerScanRole()
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
	ss := f.WorkerScanSetting(t, bindingName+"-ss")
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
			Name:     ss.Name,
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
	err = f.AssertScanGUIDMatches("ocp4-moderate-node-"+role, f.OperatorNamespace, profileGUIDOCPModerateNode)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanGUIDMatches("rhcos4-moderate-"+role, f.OperatorNamespace, profileGUIDRHCOSModerate)
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
	err = f.AssertResultsGUIDMatches("ocp4-moderate-node-"+role, f.OperatorNamespace, profileGUIDOCPModerateNode)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertResultsGUIDMatches("ocp4-moderate-node-master", f.OperatorNamespace, profileGUIDOCPModerateNode)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertResultsGUIDMatches("rhcos4-moderate-"+role, f.OperatorNamespace, profileGUIDRHCOSModerate)
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
	t.Parallel()
	f := framework.Global
	// Changes the cluster OAuth config, as does TestTokenRulesPassOauthClientsConfigurable.
	f.HoldScanLocks(t, "cluster-oauth")
	suiteName := "test-suite-two-scans-with-platform"

	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	// Scan the spare workers, not the lane nodes other tests reboot.
	selectWorkers := f.WorkerScanSelector()

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

func TestRemoveProfileScan(t *testing.T) {
	f := framework.Global
	f.HoldScanLocks(t, "ocp4-cis", "ocp4-moderate", "ocp4-cis-node")
	// Bind the new ScanSetting to a Profile
	bindingName := framework.GetObjNameFromTest(t) + "-binding"
	role := f.WorkerScanRole()
	ss := f.WorkerScanSetting(t, framework.GetObjNameFromTest(t)+"-ss")
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
			Name:     ss.Name,
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

	if err := f.AssertScanExists("ocp4-cis-node-"+role, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}

	scanName := "ocp4-moderate"
	checkResult := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-audit-profile-set", scanName),
			Namespace: f.OperatorNamespace,
		},
		ID: "xccdf_org.ssgproject.content_rule_audit_profile_set",
	}
	// This rule passes only when the cluster's audit profile is
	// WriteRequestBodies or stricter. In the serial suite it passed because
	// TestVariableTemplate had set that profile and never restored it, so
	// check that the scan produced the result, whatever its status.
	got := &compv1alpha1.ComplianceCheckResult{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: checkResult.Name, Namespace: checkResult.Namespace}, got); err != nil {
		t.Fatal(err)
	}
	if got.ID != checkResult.ID {
		t.Fatalf("expected ID %s got ID %s", checkResult.ID, got.ID)
	}
	if got.Labels[compv1alpha1.SuiteLabel] != bindingName {
		t.Fatalf("expected suite label %s, got %s", bindingName, got.Labels[compv1alpha1.SuiteLabel])
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
		if lastErr := f.AssertScanDoesNotExist("ocp4-cis-node-"+role, f.OperatorNamespace); lastErr != nil {
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
		log.Printf("Scan ocp4-moderate, ocp4-cis-node-master and ocp4-cis-node-%s do not exist anymore\n", role)
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

func TestResultServerNodeSelectorMaster(t *testing.T) {
	t.Parallel()
	f := framework.Global
	name := framework.GetObjNameFromTest(t)

	// The result servers must follow the ScanSetting's master nodeSelector.
	ss := f.WorkerScanSetting(t, name+"-master-ss", func(ss *compv1alpha1.ScanSetting) {
		ss.RawResultStorage.NodeSelector = map[string]string{"node-role.kubernetes.io/master": ""}
		ss.RawResultStorage.Tolerations = []corev1.Toleration{
			{Key: "node-role.kubernetes.io/master", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
		}
	})
	// The node selection doesn't depend on the profile: a TailoredProfile of
	// the small rhcos4-e8 profile gives this test its own, quick scans.
	tp := f.ExtendingTailoredProfile(t, name+"-e8", "rhcos4-e8")

	b := name + "-master-ns"
	ssb := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{Name: b, Namespace: f.OperatorNamespace},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     tp.Name,
				Kind:     "TailoredProfile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			Name:     ss.Name,
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

	if _, err := f.WaitForResultServerPodsWithNodeSelector(map[string]string{"node-role.kubernetes.io/master": ""}, tp.Name+"-master", tp.Name+"-"+f.WorkerScanRole()); err != nil {
		t.Fatal(err)
	}
	if err := f.WaitForSuiteScansStatusAnyResult(f.OperatorNamespace, b, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant, compv1alpha1.ResultCompliant); err != nil {
		t.Fatalf("ComplianceSuite %s did not complete: %v", b, err)
	}
}

func TestResultServerNodeSelectorWorker(t *testing.T) {
	t.Parallel()
	f := framework.Global
	name := framework.GetObjNameFromTest(t)

	// The result servers must follow the ScanSetting's worker nodeSelector.
	ss := f.WorkerScanSetting(t, name+"-worker-ss", func(ss *compv1alpha1.ScanSetting) {
		// A worker selector, narrowed to the spare workers so the result
		// servers stay off the lane nodes other tests reboot.
		sel := f.WorkerScanSelector()
		sel["node-role.kubernetes.io/worker"] = ""
		ss.RawResultStorage.NodeSelector = sel
	})
	// The node selection doesn't depend on the profile: a TailoredProfile of
	// the small rhcos4-e8 profile gives this test its own, quick scans.
	tp := f.ExtendingTailoredProfile(t, name+"-e8", "rhcos4-e8")

	b := name + "-worker-ns"
	ssb := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{Name: b, Namespace: f.OperatorNamespace},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     tp.Name,
				Kind:     "TailoredProfile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			Name:     ss.Name,
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

	if _, err := f.WaitForResultServerPodsWithNodeSelector(map[string]string{"node-role.kubernetes.io/worker": ""}, tp.Name+"-master", tp.Name+"-"+f.WorkerScanRole()); err != nil {
		t.Fatal(err)
	}
	if err := f.WaitForSuiteScansStatusAnyResult(f.OperatorNamespace, b, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant, compv1alpha1.ResultCompliant); err != nil {
		t.Fatalf("ComplianceSuite %s did not complete: %v", b, err)
	}
}

// TestHighProfileManualRulesHaveInstructions verifies that all MANUAL rules in high profiles have instructions.
// This test is serial because high profile scans are resource-intensive and long-running.
func TestHighProfileManualRulesHaveInstructions(t *testing.T) {
	f := framework.Global
	f.HoldScanLocks(t, "ocp4-high", "ocp4-high-node", "rhcos4-high")

	suiteName := framework.GetObjNameFromTest(t)
	scanSettingBinding := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "Profile",
				Name:     "ocp4-high",
			},
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "Profile",
				Name:     "ocp4-high-node",
			},
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "Profile",
				Name:     "rhcos4-high",
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}

	// Create the ScanSettingBinding
	if err := f.Client.Create(context.TODO(), &scanSettingBinding, nil); err != nil {
		t.Fatalf("Failed to create ScanSettingBinding: %s", err)
	}
	defer f.Client.Delete(context.TODO(), &scanSettingBinding)

	// Wait for the suite to complete
	if err := f.WaitForSuiteScansStatusAnyResult(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant, compv1alpha1.ResultNonCompliant, compv1alpha1.ResultInconsistent); err != nil {
		t.Fatalf("Failed waiting for suite to complete: %s", err)
	}

	// Get all MANUAL ComplianceCheckResults for this suite
	checkResults := &compv1alpha1.ComplianceCheckResultList{}
	if err := f.Client.List(context.TODO(), checkResults,
		client.InNamespace(f.OperatorNamespace),
		client.MatchingLabels{
			compv1alpha1.ComplianceCheckResultStatusLabel: string(compv1alpha1.CheckResultManual),
			compv1alpha1.SuiteLabel:                       suiteName,
		},
	); err != nil {
		t.Fatalf("Failed to list ComplianceCheckResults: %s", err)
	}

	if len(checkResults.Items) == 0 {
		t.Fatalf("No MANUAL check results found for suite %s", suiteName)
	}

	t.Logf("Found %d MANUAL check results to verify", len(checkResults.Items))

	// Check that all MANUAL rules have instructions
	var rulesWithoutInstructions []string
	for _, checkResult := range checkResults.Items {
		if checkResult.Instructions == "" {
			rulesWithoutInstructions = append(rulesWithoutInstructions, checkResult.Name)
			t.Logf("MANUAL rule '%s' does not have instructions", checkResult.Name)
		} else {
			t.Logf("MANUAL rule '%s' has instructions", checkResult.Name)
		}
	}

	if len(rulesWithoutInstructions) > 0 {
		t.Fatalf("Found %d MANUAL rules without instructions: %v", len(rulesWithoutInstructions), rulesWithoutInstructions)
	}

	t.Logf("All %d MANUAL rules in high profiles have instructions", len(checkResults.Items))
}

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
	t.Parallel()
	f := framework.Global
	// Changes the cluster OAuth clients; see TestPlatformAndNodeSuiteScan.
	f.HoldScanLocks(t, "cluster-oauth")
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
	t.Parallel()
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

	ss := f.WorkerScanSetting(t, tpName+"-ss")
	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{Name: tpName, Kind: "TailoredProfile", APIGroup: "compliance.openshift.io/v1alpha1"},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			Name: ss.Name, Kind: "ScanSetting", APIGroup: "compliance.openshift.io/v1alpha1",
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
