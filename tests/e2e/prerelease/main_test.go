package prerelease_e2e

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestMain(m *testing.M) {
	f := framework.NewFramework()
	err := f.SetUp()
	if err != nil {
		log.Fatal(err)
	}

	exitCode := m.Run()
	if exitCode == 0 || (exitCode > 0 && f.CleanUpOnError()) {
		if err = f.TearDown(); err != nil {
			log.Fatal(err)
		}
	}
	os.Exit(exitCode)
}

// TestKubeletTLSCipherSuitesVariable ports test case 50505.
// It validates fail -> auto-remediation applied -> rescan -> pass flow for
// ocp4-kubelet-configure-tls-cipher-suites using tailored profile variables.
func TestKubeletTLSCipherSuitesVariable(t *testing.T) {
	f := framework.Global
	arch, err := f.GetClusterArchitecture()
	if err != nil {
		t.Fatalf("failed to get cluster architecture: %v", err)
	}
	if arch == "arm64" || arch == "multi" || arch == "s390x" {
		t.Skipf("skipping on architecture %s (upstream parity)", arch)
	}

	const (
		roleName          = "wrscan"
		mcpName           = "wrscan"
		kubeletConfigName = "compliance-operator-kubelet-wrscan"
	)

	// Avoid the worker reserved for framework SetUp's "e2e" MachineConfigPool; labeling
	// that node for wrscan overlaps MCPs and often leaves MCO state Degraded.
	nodeName, err := f.GetOneRhcosWorkerNodeForCustomMCP()
	if err != nil {
		t.Skipf("skipping test: %v", err)
	}
	if err := f.SetNodeRoleLabel(nodeName, roleName); err != nil {
		t.Fatalf("failed to label node %s: %v", nodeName, err)
	}

	if err := f.EnsureMachineConfigPoolForRole(mcpName, roleName); err != nil {
		t.Fatalf("failed ensuring MachineConfigPool %s: %v", mcpName, err)
	}

	base := framework.GetObjNameFromTest(t)
	tpName := base + "-tp"
	ssName := base + "-ss"
	ssbName := base + "-ssb"
	scanName := fmt.Sprintf("%s-%s", tpName, roleName)
	checkName := fmt.Sprintf("%s-%s-kubelet-configure-tls-cipher-suites", tpName, roleName)
	remName := checkName

	// ssbCreated gates pause/remediation cleanup; must run before unlabel. Order below matches
	// restoreNodeLabelsForPool / TearDown: unapply → unlabel → wait node on worker → delete custom MCP → wait worker.
	var ssbCreated bool
	defer func() {
		if ssbCreated {
			_ = f.PauseMachinePool(mcpName)
			_ = f.SetSuiteRemediationsApply(f.OperatorNamespace, ssbName, false)
			_ = f.ResumeMachinePool(mcpName)
		}
		if err := f.RemoveNodeRoleLabel(nodeName, roleName); err != nil {
			t.Logf("cleanup: remove node label %s from %s: %v", roleName, nodeName, err)
		}
		if err := f.WaitForNodeToMatchMachineConfigPool("worker", nodeName); err != nil {
			t.Logf("cleanup: wait for node %s to match worker pool before deleting %s MCP: %v", nodeName, mcpName, err)
		}
		pool := &mcfgv1.MachineConfigPool{ObjectMeta: metav1.ObjectMeta{Name: mcpName}}
		if err := f.Client.Delete(context.TODO(), pool); err != nil {
			t.Logf("cleanup: delete mcp %s: %v", mcpName, err)
		}
		if err := f.WaitForMachineConfigPoolUpdated("worker"); err != nil {
			t.Logf("cleanup: wait for worker MachineConfigPool after wrscan cleanup: %v", err)
		}
	}()

	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
			Annotations: map[string]string{
				compv1alpha1.ProductTypeAnnotation: "Node",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "kubelet tls cipher suites",
			Description: "Ported from test case 50505",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-kubelet-configure-tls-cipher-suites",
					Rationale: "Node",
				},
			},
			SetValues: []compv1alpha1.VariableValueSpec{
				{
					Name:      "ocp4-var-kubelet-tls-cipher-suites-regex",
					Rationale: "Node",
					Value:     "^(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256|TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384|TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384|TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)$",
				},
				{
					Name:      "ocp4-var-kubelet-tls-cipher-suites",
					Rationale: "Node",
					Value:     "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
				},
			},
		},
	}
	if err := f.Client.Create(context.TODO(), tp, nil); err != nil {
		t.Fatalf("failed to create tailored profile %s: %v", tpName, err)
	}
	defer f.Client.Delete(context.TODO(), tp)
	if err := f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpName, compv1alpha1.TailoredProfileStateReady); err != nil {
		t.Fatalf("tailored profile %s not ready: %v", tpName, err)
	}

	ss := &compv1alpha1.ScanSetting{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ssName,
			Namespace: f.OperatorNamespace,
		},
		ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
			AutoApplyRemediations:  true,
			AutoUpdateRemediations: true,
			Schedule:               "0 1 * * *",
		},
		ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
			StrictNodeScan: func() *bool { b := false; return &b }(),
			RawResultStorage: compv1alpha1.RawResultStorageSettings{
				Size:     "2Gi",
				Rotation: 5,
			},
			Debug: true,
		},
		Roles: []string{roleName},
	}
	if err := f.Client.Create(context.TODO(), ss, nil); err != nil {
		t.Fatalf("failed to create scansetting %s: %v", ssName, err)
	}
	defer f.Client.Delete(context.TODO(), ss)

	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ssbName,
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
			Name:     ssName,
		},
	}
	if err := f.Client.Create(context.TODO(), ssb, nil); err != nil {
		t.Fatalf("failed to create scansettingbinding %s: %v", ssbName, err)
	}
	ssbCreated = true
	defer func() {
		if err := f.DeleteScanSettingBindingAndWaitForCleanup(ssb); err != nil {
			t.Logf("cleanup scansettingbinding %s: %v", ssbName, err)
		}
	}()

	// First run: suite should be done and non-compliant, check should fail, remediation should be applied.
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, ssbName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatalf("suite %s first run not done/non-compliant: %v", ssbName, err)
	}

	failCheck := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      checkName,
			Namespace: f.OperatorNamespace,
		},
		ID:       "xccdf_org.ssgproject.content_rule_kubelet_configure_tls_cipher_suites",
		Status:   compv1alpha1.CheckResultFail,
		Severity: compv1alpha1.CheckResultSeverityMedium,
	}
	if err := f.AssertHasCheck(ssbName, scanName, failCheck); err != nil {
		t.Fatalf("expected FAIL check %s after first run: %v", checkName, err)
	}

	if err := f.WaitForGenericRemediationToBeAutoApplied(remName, f.OperatorNamespace); err != nil {
		t.Fatalf("remediation %s was not auto-applied: %v", remName, err)
	}

	// Rescan and verify pass.
	if err := f.ReRunScan(scanName, f.OperatorNamespace); err != nil {
		t.Fatalf("failed to trigger rescan for %s: %v", scanName, err)
	}
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, ssbName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant); err != nil {
		t.Fatalf("suite %s second run not done/compliant: %v", ssbName, err)
	}

	passCheck := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      checkName,
			Namespace: f.OperatorNamespace,
		},
		ID:       "xccdf_org.ssgproject.content_rule_kubelet_configure_tls_cipher_suites",
		Status:   compv1alpha1.CheckResultPass,
		Severity: compv1alpha1.CheckResultSeverityMedium,
	}
	if err := f.AssertHasCheck(ssbName, scanName, passCheck); err != nil {
		t.Fatalf("expected PASS check %s after rescan: %v", checkName, err)
	}

	// Best-effort cleanup for generated kubeletconfig.
	kc := &mcfgv1.KubeletConfig{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: kubeletConfigName}, kc); err == nil {
		if err := f.Client.Delete(context.TODO(), kc); err != nil {
			t.Logf("cleanup kubeletconfig %s: %v", kubeletConfigName, err)
		}
	}
}

