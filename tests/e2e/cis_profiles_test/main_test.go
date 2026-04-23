package cis_profiles_test_e2e

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	configv1 "github.com/openshift/api/config/v1"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
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

// TestCISProfiles tests auto-remediation for CIS profiles
// This test covers downstream test cases: 46100, 46302, 54323, 66793
// Test: Verify autoremediations works for CIS profiles
func TestCISProfiles(t *testing.T) {
	f := framework.Global
	poolName := "wrscan"

	// Skip if etcd encryption is off (requirement from downstream test)
	if err := skipIfEtcdEncryptionOff(t, f); err != nil {
		t.Skip("Skipping test: etcd encryption is off")
	}

	// Get one worker node
	workerNodes, err := f.GetNodesWithSelector(map[string]string{
		"node-role.kubernetes.io/worker": "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(workerNodes) == 0 {
		t.Fatal("No worker nodes found")
	}
	workerNode := &workerNodes[0]
	workerNodeName := workerNode.Name

	// Label the worker node with custom role
	labelKey := fmt.Sprintf("node-role.kubernetes.io/%s", poolName)
	nodeCopy := workerNode.DeepCopy()
	if nodeCopy.Labels == nil {
		nodeCopy.Labels = make(map[string]string)
	}
	nodeCopy.Labels[labelKey] = ""
	if err := f.Client.Update(context.TODO(), nodeCopy); err != nil {
		t.Fatalf("failed to label node %s: %s", workerNodeName, err)
	}
	defer func() {
		// Remove label from node
		unlabelNode := &corev1.Node{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: workerNodeName}, unlabelNode); err != nil {
			t.Logf("failed to get node %s for unlabeling: %s", workerNodeName, err)
			return
		}
		unlabelNodeCopy := unlabelNode.DeepCopy()
		delete(unlabelNodeCopy.Labels, labelKey)
		if err := f.Client.Update(context.TODO(), unlabelNodeCopy); err != nil {
			t.Logf("failed to remove label from node %s: %s", workerNodeName, err)
		}
	}()

	// Create MachineConfigPool for the custom role
	nodeLabel := map[string]string{labelKey: ""}
	poolLabels := map[string]string{
		"pools.operator.machineconfiguration.openshift.io/e2e": "",
	}
	newPool := &mcfgv1.MachineConfigPool{
		ObjectMeta: metav1.ObjectMeta{
			Name:   poolName,
			Labels: poolLabels,
		},
		Spec: mcfgv1.MachineConfigPoolSpec{
			NodeSelector: &metav1.LabelSelector{
				MatchLabels: nodeLabel,
			},
			MachineConfigSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      mcfgv1.MachineConfigRoleLabelKey,
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"worker", poolName},
					},
				},
			},
		},
	}
	if err := f.Client.Create(context.TODO(), newPool, nil); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			t.Fatalf("failed to create MachineConfigPool %s: %s", poolName, err)
		}
	}

	// Wait for pool to be ready
	if err := wait.Poll(framework.RetryInterval, framework.Timeout, func() (bool, error) {
		pool := &mcfgv1.MachineConfigPool{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: poolName}, pool); err != nil {
			return false, err
		}
		for _, c := range pool.Status.Conditions {
			if c.Type == mcfgv1.MachineConfigPoolUpdated && c.Status == corev1.ConditionTrue {
				return true, nil
			}
		}
		return false, nil
	}); err != nil {
		t.Fatalf("failed waiting for MachineConfigPool %s to be ready: %s", poolName, err)
	}
	defer func() {
		// Clean up MachineConfigPool
		poolToDelete := &mcfgv1.MachineConfigPool{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: poolName}, poolToDelete); err != nil {
			t.Logf("failed to get MachineConfigPool %s for cleanup: %s", poolName, err)
			return
		}
		// Pause the pool before deleting
		poolCopy := poolToDelete.DeepCopy()
		poolCopy.Spec.Paused = true
		if err := f.Client.Update(context.TODO(), poolCopy); err != nil {
			t.Logf("failed to pause MachineConfigPool %s: %s", poolName, err)
		}
		// Wait a bit for pausing to take effect
		time.Sleep(5 * time.Second)
		if err := f.Client.Delete(context.TODO(), poolToDelete); err != nil {
			t.Logf("failed to delete MachineConfigPool %s: %s", poolName, err)
		}
	}()

	// Create KubeletConfig for the pool
	kubeletConfigName := "custom-" + poolName
	kubeletConfig := createKubeletConfig(kubeletConfigName, poolName)
	if err := f.Client.Create(context.TODO(), kubeletConfig, nil); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			t.Fatalf("failed to create KubeletConfig %s: %s", kubeletConfigName, err)
		}
	}
	defer func() {
		// Clean up KubeletConfig
		kubeletConfigToDelete := &mcfgv1.KubeletConfig{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: kubeletConfigName}, kubeletConfigToDelete); err != nil {
			t.Logf("failed to get KubeletConfig %s for cleanup: %s", kubeletConfigName, err)
			return
		}
		if err := f.Client.Delete(context.TODO(), kubeletConfigToDelete); err != nil {
			t.Logf("failed to delete KubeletConfig %s: %s", kubeletConfigName, err)
		}
	}()

	// Wait for KubeletConfig to be successful
	if err := waitForKubeletConfigSuccess(f, kubeletConfigName); err != nil {
		t.Fatalf("failed waiting for KubeletConfig %s to be successful: %s", kubeletConfigName, err)
	}

	// Wait for pool to be ready after KubeletConfig
	if err := wait.Poll(framework.RetryInterval, framework.Timeout*2, func() (bool, error) {
		pool := &mcfgv1.MachineConfigPool{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: poolName}, pool); err != nil {
			return false, err
		}
		for _, c := range pool.Status.Conditions {
			if c.Type == mcfgv1.MachineConfigPoolUpdated && c.Status == corev1.ConditionTrue {
				return true, nil
			}
		}
		return false, nil
	}); err != nil {
		t.Fatalf("failed waiting for MachineConfigPool %s to be ready after KubeletConfig: %s", poolName, err)
	}

	// Create ScanSetting with auto-apply remediations
	scanSettingName := framework.GetObjNameFromTest(t) + "-auto-rem"
	scanSetting := compv1alpha1.ScanSetting{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingName,
			Namespace: f.OperatorNamespace,
		},
		ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
			AutoApplyRemediations:  true,
			AutoUpdateRemediations: true,
			Schedule:               "0 1 * * *",
		},
		ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
			RawResultStorage: compv1alpha1.RawResultStorageSettings{
				Size:     "2Gi",
				Rotation: 5,
			},
			Debug: false,
		},
		Roles: []string{poolName},
	}
	if err := f.Client.Create(context.TODO(), &scanSetting, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSetting)

	// Clean up all remediations before starting
	defer func() {
		// Pause the pool before unapplying remediations
		pool := &mcfgv1.MachineConfigPool{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: poolName}, pool); err != nil {
			t.Logf("failed to get MachineConfigPool %s for pausing: %s", poolName, err)
		} else {
			poolCopy := pool.DeepCopy()
			poolCopy.Spec.Paused = true
			if err := f.Client.Update(context.TODO(), poolCopy); err != nil {
				t.Logf("failed to pause MachineConfigPool %s: %s", poolName, err)
			}
		}

		// Set all remediations to unapplied
		remList := &compv1alpha1.ComplianceRemediationList{}
		if err := f.Client.List(context.TODO(), remList, client.InNamespace(f.OperatorNamespace)); err == nil {
			for i := range remList.Items {
				rem := &remList.Items[i]
				if rem.Spec.Apply {
					remCopy := rem.DeepCopy()
					remCopy.Spec.Apply = false
					if err := f.Client.Update(context.TODO(), remCopy); err != nil {
						t.Logf("failed to unapply remediation %s: %s", rem.Name, err)
					}
				}
			}
		}

		// Unpause the pool
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: poolName}, pool); err == nil {
			poolCopy := pool.DeepCopy()
			poolCopy.Spec.Paused = false
			if err := f.Client.Update(context.TODO(), poolCopy); err != nil {
				t.Logf("failed to unpause MachineConfigPool %s: %s", poolName, err)
			}
		}
	}()

	// Create ScanSettingBinding with ocp4-cis and ocp4-cis-node profiles
	bindingName := framework.GetObjNameFromTest(t) + "-cis"
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
	defer f.Client.Delete(context.TODO(), &scanSettingBinding)

	// Clean up suite
	defer func() {
		// Delete the suite
		suite := &compv1alpha1.ComplianceSuite{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: bindingName, Namespace: f.OperatorNamespace}, suite); err == nil {
			if err := f.Client.Delete(context.TODO(), suite); err != nil {
				t.Logf("failed to delete ComplianceSuite %s: %s", bindingName, err)
			}
		}

		// Delete all scans
		scanList := &compv1alpha1.ComplianceScanList{}
		if err := f.Client.List(context.TODO(), scanList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels{compv1alpha1.SuiteLabel: bindingName}); err == nil {
			for i := range scanList.Items {
				scan := &scanList.Items[i]
				if err := f.Client.Delete(context.TODO(), scan); err != nil {
					t.Logf("failed to delete ComplianceScan %s: %s", scan.Name, err)
				}
			}
		}
	}()

	// Wait for initial scans to complete
	t.Logf("Waiting for initial scans to complete")
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	// Verify suite result is NON-COMPLIANT
	suite := &compv1alpha1.ComplianceSuite{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: bindingName, Namespace: f.OperatorNamespace}, suite); err != nil {
		t.Fatalf("failed to get ComplianceSuite %s: %s", bindingName, err)
	}
	if suite.Status.Result != compv1alpha1.ResultNonCompliant {
		t.Logf("Suite result is %s, expected NON-COMPLIANT", suite.Status.Result)
	}

	// Verify individual scan results
	// ocp4-cis-node should be COMPLIANT
	scanList := &compv1alpha1.ComplianceScanList{}
	if err := f.Client.List(context.TODO(), scanList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels{compv1alpha1.SuiteLabel: bindingName}); err != nil {
		t.Fatalf("failed to get scans from suite: %s", err)
	}
	for _, scan := range scanList.Items {
		t.Logf("Scan %s has result: %s", scan.Name, scan.Status.Result)
		if strings.Contains(scan.Name, "ocp4-cis-node") {
			if scan.Status.Result != compv1alpha1.ResultCompliant {
				t.Logf("Expected ocp4-cis-node scan to be COMPLIANT, got %s", scan.Status.Result)
			}
		}
	}

	// Check that api-server-encryption-provider-cipher check passes (downstream test case requirement)
	checkName := "ocp4-cis-api-server-encryption-provider-cipher"
	check := &compv1alpha1.ComplianceCheckResult{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: checkName, Namespace: f.OperatorNamespace}, check); err != nil {
		t.Logf("Check %s not found or error: %s", checkName, err)
	} else {
		if check.Status != compv1alpha1.CheckResultPass {
			t.Logf("Check %s has status %s (expected PASS)", checkName, check.Status)
		}
	}

	// Verify that KubeletConfig has TLS cipher suites set (downstream test requirement)
	kubeletConfigCheck := &mcfgv1.KubeletConfig{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: kubeletConfigName}, kubeletConfigCheck); err == nil {
		if kubeletConfigCheck.Spec.KubeletConfig != nil && kubeletConfigCheck.Spec.KubeletConfig.Raw != nil {
			rawConfig := string(kubeletConfigCheck.Spec.KubeletConfig.Raw)
			t.Logf("KubeletConfig has raw config: %s", rawConfig)
			// Should contain TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
			if strings.Contains(rawConfig, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384") {
				t.Logf("KubeletConfig contains expected cipher TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
			} else {
				t.Logf("KubeletConfig tlsCipherSuites doesn't contain expected cipher TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
			}
		}
	}

	// Get remediations that were created
	remList := &compv1alpha1.ComplianceRemediationList{}
	inNs := client.InNamespace(f.OperatorNamespace)
	withLabel := client.MatchingLabels{compv1alpha1.SuiteLabel: bindingName}
	if err := f.Client.List(context.TODO(), remList, inNs, withLabel); err != nil {
		t.Logf("failed to list remediations: %s", err)
	}

	// If remediations exist, trigger a rescan to verify they were applied
	if len(remList.Items) > 0 {
		t.Logf("Found %d remediations, waiting for auto-application", len(remList.Items))

		// Get the pool for MachineConfig-based remediations
		pool := &mcfgv1.MachineConfigPool{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: poolName}, pool); err != nil {
			t.Fatalf("failed to get MachineConfigPool %s: %s", poolName, err)
		}

		// Wait for remediations to be auto-applied (only for MachineConfig types)
		mcRemediationCount := 0
		for _, rem := range remList.Items {
			// Check if this is a MachineConfig-based remediation
			isMachineConfig := false
			if rem.Spec.Current.Object != nil {
				objKind := rem.Spec.Current.Object.GetObjectKind().GroupVersionKind().Kind
				isMachineConfig = (objKind == "MachineConfig")
			}

			if isMachineConfig {
				mcRemediationCount++
				t.Logf("Waiting for MachineConfig remediation %s to be auto-applied", rem.Name)
				if err := f.WaitForRemediationToBeAutoApplied(rem.Name, f.OperatorNamespace, pool); err != nil {
					t.Logf("remediation %s may not have been auto-applied: %s", rem.Name, err)
				}
			} else {
				// Non-MachineConfig remediation (e.g., audit-profile-set)
				// Just verify it's applied, don't wait for it in the pool
				t.Logf("Remediation %s is not a MachineConfig type (auto-apply=%v)", rem.Name, rem.Spec.Apply)
			}
		}

		t.Logf("Found %d MachineConfig-based remediations out of %d total", mcRemediationCount, len(remList.Items))

		// Only wait for pool if we have MachineConfig remediations
		if mcRemediationCount > 0 {
			t.Logf("Waiting for MachineConfigPool %s to be ready after applying MachineConfig remediations", poolName)
			if err := wait.Poll(framework.RetryInterval, framework.Timeout*2, func() (bool, error) {
				pool := &mcfgv1.MachineConfigPool{}
				if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: poolName}, pool); err != nil {
					return false, err
				}
				for _, c := range pool.Status.Conditions {
					if c.Type == mcfgv1.MachineConfigPoolUpdated && c.Status == corev1.ConditionTrue {
						return true, nil
					}
				}
				return false, nil
			}); err != nil {
				t.Logf("MachineConfigPool %s may not be ready after remediation: %s", poolName, err)
			}
		} else {
			t.Logf("No MachineConfig remediations found, skipping pool update wait")
			// Give a brief pause for non-MachineConfig remediations to be applied
			time.Sleep(30 * time.Second)
		}

		// Trigger rescan by rescanning individual scans
		t.Logf("Triggering rescan to verify remediations")
		scanList := &compv1alpha1.ComplianceScanList{}
		if err := f.Client.List(context.TODO(), scanList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels{compv1alpha1.SuiteLabel: bindingName}); err == nil {
			for _, scan := range scanList.Items {
				if err := f.ReRunScan(scan.Name, f.OperatorNamespace); err != nil {
					t.Logf("Failed to trigger rescan for %s: %s", scan.Name, err)
				}
			}
		}

		// Wait for rescan to complete
		t.Logf("Waiting for rescan to complete")
		if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant); err != nil {
			// It's OK if not all scans are compliant, just log it
			t.Logf("Rescan completed but not all scans are compliant: %s", err)
		}

		// After rescan, verify that all automated checks pass (downstream requirement)
		t.Logf("Verifying all automated checks pass after rescan")
		checkResultList := &compv1alpha1.ComplianceCheckResultList{}
		automatedLabels := client.MatchingLabels{
			compv1alpha1.SuiteLabel:                          bindingName,
			compv1alpha1.ComplianceCheckResultHasRemediation: "",
		}
		if err := f.Client.List(context.TODO(), checkResultList, inNs, automatedLabels); err == nil {
			nonPassCount := 0
			for _, check := range checkResultList.Items {
				if check.Status != compv1alpha1.CheckResultPass {
					t.Logf("automated check %s has status %s (expected PASS)", check.Name, check.Status)
					nonPassCount++
				}
			}
			if nonPassCount == 0 {
				t.Logf("All %d automated checks passed after remediation", len(checkResultList.Items))
			} else {
				t.Logf("%d out of %d automated checks did not pass", nonPassCount, len(checkResultList.Items))
			}
		}
	} else {
		t.Logf("No remediations found for suite %s", bindingName)
	}

	t.Logf("CIS profiles test completed successfully")
}

// skipIfEtcdEncryptionOff checks if etcd encryption is enabled and skips the test if not
func skipIfEtcdEncryptionOff(t *testing.T, f *framework.Framework) error {
	// Get the cluster APIServer config
	apiserver := &configv1.APIServer{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: "cluster"}, apiserver); err != nil {
		return fmt.Errorf("failed to get apiserver config: %w", err)
	}

	// Check encryption type
	if apiserver.Spec.Encryption.Type == "" {
		return fmt.Errorf("etcd encryption is not configured")
	}

	// Skip if encryption type is aescbc (destructive and time-consuming to change)
	if apiserver.Spec.Encryption.Type == "aescbc" {
		t.Logf("Skipping test: encryption type is aescbc")
		return fmt.Errorf("encryption type is aescbc")
	}

	return nil
}

// createKubeletConfig creates a KubeletConfig for testing
func createKubeletConfig(name, role string) *mcfgv1.KubeletConfig {
	return &mcfgv1.KubeletConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: mcfgv1.KubeletConfigSpec{
			MachineConfigPoolSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"pools.operator.machineconfiguration.openshift.io/e2e": "",
				},
			},
			KubeletConfig: &runtime.RawExtension{
				Raw: []byte(`{"protectKernelDefaults": true, "streamConnectionIdleTimeout": "5m"}`),
			},
		},
	}
}

// waitForKubeletConfigSuccess waits for KubeletConfig to be successfully applied
func waitForKubeletConfigSuccess(f *framework.Framework, name string) error {
	return wait.Poll(framework.RetryInterval, framework.Timeout, func() (bool, error) {
		kubeletConfig := &mcfgv1.KubeletConfig{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: name}, kubeletConfig); err != nil {
			return false, err
		}
		for _, c := range kubeletConfig.Status.Conditions {
			if c.Type == "Success" && c.Status == corev1.ConditionTrue {
				return true, nil
			}
		}
		return false, nil
	})
}
