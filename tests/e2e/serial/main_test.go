package serial_e2e

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	mcfgv1 "github.com/openshift/machine-config-operator/pkg/apis/machineconfiguration.openshift.io/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

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
			Profile: "xccdf_org.ssgproject.content_profile_moderate",
			Content: framework.RhcosContentFile,
			Rule:    "xccdf_org.ssgproject.content_rule_no_netrc_files",
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
			Status:   compv1alpha1.CheckResultInfo,
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

	// The test should not leave junk around, let's remove the MC and wait for the nodes to stabilize
	// again
	log.Printf("Removing applied remediation\n")
	// Fetch remediation here so it can be deleted
	rem := &compv1alpha1.ComplianceRemediation{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: remName, Namespace: f.OperatorNamespace}, rem)
	if err != nil {
		t.Fatal(err)
	}
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
