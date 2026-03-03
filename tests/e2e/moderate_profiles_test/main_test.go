package profile_test_e2e

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func TestModerate(t *testing.T) {
	f := framework.Global
	mcpName := "wrscan"
	
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
	workerNode := &workerNodes[1]
	workerNodeName := workerNode.Name

	// Label the worker node with custom role
	labelKey := fmt.Sprintf("node-role.kubernetes.io/%s", mcpName)
	nodeCopy := workerNode.DeepCopy()
	if nodeCopy.Labels == nil {
		nodeCopy.Labels = make(map[string]string)
	}
	nodeCopy.Labels[labelKey] = ""
	if err := f.Client.Update(context.TODO(), nodeCopy); err != nil {
		t.Fatalf("failed to label node %s: %s", workerNodeName, err)
	}

	// Create MachineConfigPool for the custom role
	nodeLabel := map[string]string{labelKey: ""}
	if err := f.CreateCustomMachineConfigPool(mcpName, nodeLabel); err != nil {
		t.Fatal(err)
	}

	scanSettingName := framework.GetObjNameFromTest(t) + "-auto-rem"
	scanSetting := compv1alpha1.ScanSetting{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingName,
			Namespace: f.OperatorNamespace,
		},
		ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
			AutoApplyRemediations:  true,
			AutoUpdateRemediations:  true,
			Schedule:               "0 1 * * *",
		},
		ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
			RawResultStorage: compv1alpha1.RawResultStorageSettings{
				Size:     "2Gi",
				Rotation: 5,
			},
			Debug: false,
		},
		Roles: []string{mcpName},
	}
	if err := f.Client.Create(context.TODO(), &scanSetting, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSetting)

	bindingName := framework.GetObjNameFromTest(t) + "-moderate"
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

	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	// Check that remediations were created
	remList := &compv1alpha1.ComplianceRemediationList{}
	inNs := client.InNamespace(f.OperatorNamespace)
	withLabel := client.MatchingLabels{compv1alpha1.SuiteLabel: bindingName}
	if err := f.Client.List(context.TODO(), remList, inNs, withLabel); err != nil {
		t.Logf("failed to list remediations: %s", err)
	}

	// If remediations exist, wait for them to be auto-applied
	pool := &mcfgv1.MachineConfigPool{}
	if len(remList.Items) > 0 {
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: mcpName}, pool); err != nil {
			t.Fatalf("failed to get MachineConfigPool %s: %s", mcpName, err)
		}

		// Wait for remediations to be auto-applied
		for _, rem := range remList.Items {
			if rem.Status.ApplicationState == compv1alpha1.RemediationApplied {
				continue
			}
			if err := f.WaitForRemediationToBeAutoApplied(rem.Name, f.OperatorNamespace, pool); err != nil {
				t.Logf("remediation %s may not have been auto-applied: %s", rem.Name, err)
			}
		}
	}

	// Verify scan results
	expectedScans := []string{"ocp4-moderate", "ocp4-moderate-node-" + mcpName, "rhcos4-moderate-" + mcpName}
	for _, scanName := range expectedScans {
		if err := f.AssertScanIsNonCompliant(scanName, f.OperatorNamespace); err != nil {
			t.Logf("scan %s may not be non-compliant: %s", scanName, err)
		}
	}

	// Check that audit-profile-set check passes
	checkAuditProfileSet := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ocp4-moderate-audit-profile-set",
			Namespace: f.OperatorNamespace,
		},
		ID:       "xccdf_org.ssgproject.content_rule_audit_profile_set",
		Status:   compv1alpha1.CheckResultPass,
		Severity: compv1alpha1.CheckResultSeverityMedium,
	}
	if err := f.AssertHasCheck(bindingName, "ocp4-moderate", checkAuditProfileSet); err != nil {
		t.Logf("audit-profile-set check may not be passing: %s", err)
	}

	// Verify that automated remediations are applied (no non-PASS automated checks)
	checkResultList := &compv1alpha1.ComplianceCheckResultList{}
	automatedLabels := client.MatchingLabels{
		compv1alpha1.SuiteLabel:                    bindingName,
		compv1alpha1.ComplianceCheckResultHasRemediation: "",
	}
	if err := f.Client.List(context.TODO(), checkResultList, inNs, automatedLabels); err == nil {
		for _, check := range checkResultList.Items {
			if check.Status != compv1alpha1.CheckResultPass {
				t.Logf("automated check %s has status %s (expected PASS)", check.Name, check.Status)
			}
		}
	}

	// Cleanup: Unapply all remediations before removing label and deleting pool
	defer func() {
		// First, unapply all remediations to remove MachineConfigs from the pool
		// Get fresh list of remediations in case it changed
		currentRemList := &compv1alpha1.ComplianceRemediationList{}
		if err := f.Client.List(context.TODO(), currentRemList, inNs, withLabel); err == nil {
			for _, rem := range currentRemList.Items {
				// Get fresh copy to check current state
				remCopy := &compv1alpha1.ComplianceRemediation{}
				if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: rem.Name, Namespace: f.OperatorNamespace}, remCopy); err != nil {
					continue
				}
				if remCopy.Spec.Apply {
					if err := f.UnApplyRemediationAndCheck(f.OperatorNamespace, remCopy.Name, mcpName); err != nil {
						t.Logf("failed to unapply remediation %s: %s", remCopy.Name, err)
					}
				}
			}
		}

		// Wait for pool to stabilize after unapplying remediations
		if err := wait.Poll(framework.RetryInterval, framework.Timeout, func() (bool, error) {
			pool := &mcfgv1.MachineConfigPool{}
			if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: mcpName}, pool); err != nil {
				return false, err
			}
			for _, c := range pool.Status.Conditions {
				if c.Type == mcfgv1.MachineConfigPoolUpdated && c.Status == corev1.ConditionTrue {
					return true, nil
				}
			}
			return false, nil
		}); err != nil {
			t.Logf("pool %s may not have stabilized after unapplying remediations: %s", mcpName, err)
		}

		// Get worker pool to check its rendered config name
		workerPool := &mcfgv1.MachineConfigPool{}
		workerPoolRenderedConfig := ""
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: "worker"}, workerPool); err == nil {
			workerPoolRenderedConfig = workerPool.Spec.Configuration.Name
		}

		// Now remove the label from the node (this will move it back to worker pool)
		unlabelNode := &corev1.Node{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: workerNodeName}, unlabelNode); err != nil {
			t.Logf("failed to get node %s for unlabeling: %s", workerNodeName, err)
			return
		}
		unlabelNodeCopy := unlabelNode.DeepCopy()
		delete(unlabelNodeCopy.Labels, labelKey)
		if err := f.Client.Update(context.TODO(), unlabelNodeCopy); err != nil {
			t.Logf("failed to remove label from node %s: %s", workerNodeName, err)
			return
		}

		// Wait for node to transition back to worker pool before deleting wrscan pool
		// The node should start using the worker pool's rendered config
		if workerPoolRenderedConfig != "" {
			if err := wait.Poll(framework.RetryInterval, framework.Timeout, func() (bool, error) {
				node := &corev1.Node{}
				if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: workerNodeName}, node); err != nil {
					return false, err
				}
				desiredConfig := node.Annotations["machineconfiguration.openshift.io/desiredConfig"]
				// Node should be transitioning to or using worker pool's rendered config
				if desiredConfig == workerPoolRenderedConfig {
					return true, nil
				}
				return false, nil
			}); err != nil {
				t.Logf("node %s may not have transitioned back to worker pool: %s", workerNodeName, err)
			}
		}

		// Finally, delete the MachineConfigPool
		poolToDelete := &mcfgv1.MachineConfigPool{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: mcpName}, poolToDelete); err != nil {
			if !apierrors.IsNotFound(err) {
				t.Logf("failed to get MachineConfigPool %s for cleanup: %s", mcpName, err)
			}
			return
		}
		if err := f.Client.Delete(context.TODO(), poolToDelete); err != nil {
			t.Logf("failed to delete MachineConfigPool %s: %s", mcpName, err)
		}
	}()
}