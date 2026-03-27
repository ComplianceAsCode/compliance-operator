package prerelease_e2e

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
	corev1 "k8s.io/api/core/v1"
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

// Test TestResourceRequestsQuotaVariable validates that setting
// ocp4-var-resource-requests-quota-per-project-exempt-regex to all non-control
// namespaces makes quota checks PASS for tailored profiles extending ocp4-stig
// and ocp4-moderate.
func TestResourceRequestsQuotaVariable(t *testing.T) {
	f := framework.Global
	arch := f.ClusterArchitecture()
	if arch == framework.ArchARM64 || arch == framework.ArchMULTI || arch == framework.ArchS390X {
		t.Skipf("skipping on architecture %s (upstream parity)", arch.String())
	}

	base := framework.GetObjNameFromTest(t)
	nsTest1 := base + "-ns1"
	nsTest2 := base + "-ns2"
	tpStigName := base + "-stig"
	tpModerateName := base + "-moderate"
	ssbStigName := base + "-ssb-stig"
	ssbModerateName := base + "-ssb-moderate"

	for _, ns := range []string{nsTest1, nsTest2} {
		_, err := f.KubeClient.CoreV1().Namespaces().Create(context.TODO(), &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: ns},
		}, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("create namespace %s: %v", ns, err)
		}
		defer f.KubeClient.CoreV1().Namespaces().Delete(context.TODO(), ns, metav1.DeleteOptions{})
	}

	exemptRegex, err := f.NonControlNamespacesRegex()
	if err != nil {
		t.Fatalf("compute non-control namespaces regex: %v", err)
	}
	t.Logf("Computed exempt regex with %d chars", len(exemptRegex))

	tpStig := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpStigName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Extends:     "ocp4-stig",
			Title:       "Quota exempt regex",
			Description: "Ported from extended test case 76105",
			SetValues: []compv1alpha1.VariableValueSpec{
				{
					Name:      "ocp4-var-resource-requests-quota-per-project-exempt-regex",
					Rationale: "test",
					Value:     exemptRegex,
				},
			},
		},
	}
	tpModerate := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpModerateName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Extends:     "ocp4-moderate",
			Title:       "Quota exempt regex",
			Description: "Ported from extended test case 76105",
			SetValues: []compv1alpha1.VariableValueSpec{
				{
					Name:      "ocp4-var-resource-requests-quota-per-project-exempt-regex",
					Rationale: "test",
					Value:     exemptRegex,
				},
			},
		},
	}
	if err := f.Client.Create(context.TODO(), tpStig, nil); err != nil {
		t.Fatalf("create TailoredProfile %s: %v", tpStig.Name, err)
	}
	defer f.Client.Delete(context.TODO(), tpStig)
	if err := f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpStig.Name, compv1alpha1.TailoredProfileStateReady); err != nil {
		t.Fatalf("wait TailoredProfile %s ready: %v", tpStig.Name, err)
	}

	if err := f.Client.Create(context.TODO(), tpModerate, nil); err != nil {
		t.Fatalf("create TailoredProfile %s: %v", tpModerate.Name, err)
	}
	defer f.Client.Delete(context.TODO(), tpModerate)
	if err := f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpModerate.Name, compv1alpha1.TailoredProfileStateReady); err != nil {
		t.Fatalf("wait TailoredProfile %s ready: %v", tpModerate.Name, err)
	}

	ssbStig := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ssbStigName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     tpStigName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}
	ssbModerate := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ssbModerateName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     tpModerateName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}
	if err := f.Client.Create(context.TODO(), ssbStig, nil); err != nil {
		t.Fatalf("create ScanSettingBinding %s: %v", ssbStig.Name, err)
	}
	defer func() {
		if err := f.DeleteScanSettingBindingAndWaitForCleanup(ssbStig); err != nil {
			t.Logf("cleanup ScanSettingBinding %s failed: %v", ssbStig.Name, err)
		}
	}()

	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, ssbStig.Name, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	if err := f.Client.Create(context.TODO(), ssbModerate, nil); err != nil {
		t.Fatalf("create ScanSettingBinding %s: %v", ssbModerate.Name, err)
	}
	defer func() {
		if err := f.DeleteScanSettingBindingAndWaitForCleanup(ssbModerate); err != nil {
			t.Logf("cleanup ScanSettingBinding %s failed: %v", ssbModerate.Name, err)
		}
	}()

	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, ssbModerate.Name, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	for _, suiteName := range []string{ssbStigName, ssbModerateName} {
		suite := &compv1alpha1.ComplianceSuite{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: suiteName, Namespace: f.OperatorNamespace}, suite); err != nil {
			t.Fatalf("get suite %s: %v", suiteName, err)
		}
		for _, scanStatus := range suite.Status.ScanStatuses {
			exitCode, _, err := f.GetScanExitCodeAndErrorMsg(scanStatus.Name, f.OperatorNamespace)
			if err != nil {
				t.Fatalf("get exit code for scan %s: %v", scanStatus.Name, err)
			}
			if exitCode != "2" {
				t.Fatalf("scan %s: expected exit-code 2, got %s", scanStatus.Name, exitCode)
			}
		}
	}

	stigCheckName := fmt.Sprintf("%s-resource-requests-quota-per-project", tpStigName)
	if err := f.WaitForCheckResultStatus(stigCheckName, compv1alpha1.CheckResultPass); err != nil {
		t.Fatalf("check %s did not become PASS: %v", stigCheckName, err)
	}

	moderateCheckName := fmt.Sprintf("%s-resource-requests-quota", tpModerateName)
	if err := f.WaitForCheckResultStatus(moderateCheckName, compv1alpha1.CheckResultPass); err != nil {
		t.Fatalf("check %s did not become PASS: %v", moderateCheckName, err)
	}
}

// TestProfilesOnArch verifies that after installation, the expected
// ProfileBundles and Profiles exist for the cluster architecture.
func TestProfilesOnArch(t *testing.T) {
	f := framework.Global
	arch := f.ClusterArchitecture()
	t.Logf("detected cluster architecture: %s", arch.String())

	// Verify the ocp4 ProfileBundle exists and is valid.
	err := f.WaitForProfileBundleStatus("ocp4", compv1alpha1.DataStreamValid)
	if err != nil {
		t.Fatalf("ocp4 ProfileBundle did not become valid: %v", err)
	}

	// Conditionally verify the rhcos4 ProfileBundle.
	if framework.ExpectsRhcos4ProfileBundle(arch) {
		err = f.WaitForProfileBundleStatus("rhcos4", compv1alpha1.DataStreamValid)
		if err != nil {
			t.Fatalf("rhcos4 ProfileBundle did not become valid: %v", err)
		}
	} else {
		t.Logf("skipping rhcos4 ProfileBundle check for architecture %s", arch.String())
	}

	expected := framework.GetExpectedProfilesForArch(arch)
	t.Logf("expecting %d profiles for architecture %s", len(expected), arch.String())

	for _, profileName := range expected {
		if err := f.WaitForProfileExists(profileName, 5*time.Minute, 10*time.Second); err != nil {
			t.Errorf("profile %s not found: %v", profileName, err)
		}
	}
}

// TestAPIResourceCollectorHandlesLargeMachineConfigs verifies that the
// api-resource-collector survives a cluster carrying a large MachineConfig
// list.
//
// The collector reads every API path the content asks for into memory and
// runs under a 202Mi limit, which makes it the component that runs out of
// memory first in a large environment. What keeps it bounded on the
// MachineConfig list is mcStreamer: it pages through MachineConfigs and drops
// each one's Ignition file contents before collecting it. That paging exists
// because the collector used to be OOMKilled fetching the MachineConfigs the
// PCI-DSS profile examines.
//
// This test gives the collector far more MachineConfig content than it could
// hold unpaged, so losing either protection shows up as an OOMKill rather
// than as a quiet pass.
func TestAPIResourceCollectorHandlesLargeMachineConfigs(t *testing.T) {
	f := framework.Global

	const (
		mcCount = 60
		// Comfortably under the ~1.5Mi the API server accepts for one object.
		mcPayloadBytes = 900 * 1024
		// No MachineConfigPool selects this role, so the MachineConfigOperator
		// renders nothing from these MachineConfigs and no node reboots.
		mcRole   = "e2e-collector-load"
		mcPrefix = "99-e2e-collector-load-"
		scanName = "collector-load-scan"
		// The one path mcStreamer handles; everything else is fetched whole.
		mcListPath = "/apis/machineconfiguration.openshift.io/v1/machineconfigs"
	)

	mcNames, err := f.CreateLoadMachineConfigs(t, mcCount, mcPrefix, mcRole, mcPayloadBytes)
	defer f.DeleteLoadMachineConfigs(t, mcNames)
	if err != nil {
		t.Fatalf("Failed to create load MachineConfigs: %v", err)
	}
	t.Logf("Cluster now carries ~%d MiB of MachineConfig content", mcCount*mcPayloadBytes/(1024*1024))

	scan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			ScanType: compv1alpha1.ScanTypePlatform,
			Profile:  "xccdf_org.ssgproject.content_profile_cis",
			Content:  framework.OcpContentFile,
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				// Keep the scan pod around once the scan is done, so its init
				// container status and logs can still be read.
				Debug: true,
			},
		},
	}
	if err := f.Client.Create(context.TODO(), scan, nil); err != nil {
		t.Fatalf("Failed to create scan: %v", err)
	}
	defer f.Client.Delete(context.TODO(), scan)

	collectorPod, err := f.WaitForAPIResourceCollector(scanName, 15*time.Minute, 5*time.Second)
	if err != nil {
		t.Fatalf("api-resource-collector did not complete with %d MachineConfigs: %v", mcCount, err)
	}
	t.Logf("api-resource-collector completed in pod %s", collectorPod.Name)

	// Guard the premise. If the content stops asking for the whole
	// MachineConfig list, the load above never reaches the collector and this
	// test would keep passing without exercising anything.
	logs, err := f.GetContainerLogs(collectorPod.Name, framework.APIResourceCollectorContainer)
	if err != nil {
		t.Fatalf("Failed to read api-resource-collector logs: %v", err)
	}
	// Match the whole logged URI. The list path is a prefix of the paths that
	// name a single MachineConfig, and those are fetched whole by uriStreamer,
	// which is not what this test is about.
	if !strings.Contains(logs, fmt.Sprintf("Fetching URI: '%s'", mcListPath)) {
		t.Fatalf("api-resource-collector never fetched %s, so the %d MachineConfigs did not reach it. "+
			"The profile's content no longer requests the whole MachineConfig list, and this test "+
			"needs to be pointed at content that does.", mcListPath, mcCount)
	}

	if err := f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone); err != nil {
		t.Fatalf("Scan did not finish: %v", err)
	}
}
