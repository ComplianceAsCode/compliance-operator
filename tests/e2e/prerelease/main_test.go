package prerelease_e2e

import (
	"context"
	"fmt"
	"log"
	"os"
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

// TestProfilesOnArch (test case 45729) verifies that after the Compliance Operator is installed,
// it creates the expected default ProfileBundles (ocp4, and rhcos4 for amd64/arm64/ppc64le/multi) with status
// VALID, and that the expected Profiles exist for the cluster's architecture.
func TestProfilesOnArch(t *testing.T) {
	f := framework.Global

	arch := f.ClusterArchitecture()
	t.Logf("Detected cluster architecture: %s", arch.String())

	// 1. ocp4 ProfileBundle must always be VALID
	if err := f.WaitForProfileBundleStatus("ocp4", compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("ProfileBundle ocp4 did not reach VALID: %v", err)
	}
	t.Log("ProfileBundle ocp4 is VALID")

	// 2. rhcos4 ProfileBundle only on architectures that ship rhcos4 content (not s390x)
	if framework.ExpectsRhcos4ProfileBundle(arch) {
		if err := f.WaitForProfileBundleStatus("rhcos4", compv1alpha1.DataStreamValid); err != nil {
			t.Fatalf("ProfileBundle rhcos4 did not reach VALID: %v", err)
		}
		t.Log("ProfileBundle rhcos4 is VALID")
	} else {
		t.Logf("Skipping rhcos4 ProfileBundle check for architecture %s", arch.String())
	}

	// 3. Verify expected Profiles exist for the detected architecture
	expectedProfiles := framework.GetExpectedProfilesForArch(arch)
	if len(expectedProfiles) == 0 {
		t.Fatalf("no expected profiles defined for architecture %s", arch.String())
	}

	for _, profileName := range expectedProfiles {
		err := f.WaitForProfileExists(profileName, 10*time.Second, 2*time.Second)
		if err != nil {
			t.Fatalf("Profile %s not found in namespace %s: %v", profileName, f.OperatorNamespace, err)
		}
		t.Logf("Profile %s exists", profileName)
	}
	t.Logf("All %d expected profiles exist for architecture %s", len(expectedProfiles), arch.String())
}
