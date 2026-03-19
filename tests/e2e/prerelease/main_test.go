package prerelease_e2e

import (
	"log"
	"os"
	"testing"
	"time"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
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

// TestProfilesOnArch (test case 45729) verifies that after the Compliance Operator is installed,
// it creates the expected default ProfileBundles (ocp4, and rhcos4 for amd64/arm64/ppc64le/multi) with status
// VALID, and that the expected Profiles exist for the cluster's architecture.
func TestProfilesOnArch(t *testing.T) {
	f := framework.Global

	arch, err := f.ClusterArchitecture()
	if err != nil {
		t.Fatalf("failed to determine cluster architecture: %v", err)
	}
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
		err = f.WaitForProfileExists(profileName, 10*time.Second, 2*time.Second)
		if err != nil {
			t.Fatalf("Profile %s not found in namespace %s: %v", profileName, f.OperatorNamespace, err)
		}
		t.Logf("Profile %s exists", profileName)
	}
	t.Logf("All %d expected profiles exist for architecture %s", len(expectedProfiles), arch.String())
}
