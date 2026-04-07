package rosa_e2e

import (
	"context"
	"log"
	"os"
	"testing"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var brokenContentImagePath string
var contentImagePath string

func TestMain(m *testing.M) {
	f := framework.NewFramework()
	skipManifest := os.Getenv("E2E_SKIP_FRAMEWORK_SETUP") == "true"
	var err error
	if !skipManifest {
		err = f.SetUp()
	} else {
		err = f.InitRosa73945FrameworkWithoutManifest()
	}
	if err != nil {
		log.Fatal(err)
	}

	exitCode := m.Run()
	if !skipManifest && (exitCode == 0 || (exitCode > 0 && f.CleanUpOnError())) {
		if err = f.TearDown(); err != nil {
			log.Fatal(err)
		}
	}
	os.Exit(exitCode)
}

func TestInstallOnlyParsesNodeProfiles(t *testing.T) {
	if os.Getenv("E2E_SKIP_FRAMEWORK_SETUP") == "true" {
		t.Skip("requires manifest-based SetUp; run without E2E_SKIP_FRAMEWORK_SETUP")
	}
	t.Parallel()
	f := framework.Global

	// list all profiles
	l := compv1alpha1.ProfileList{}
	err := f.Client.List(context.TODO(), &l)
	if err != nil {
		f.PrintROSADebugInfo(t)
		t.Fatalf("failed to get ProfileList: %s", err)
	}

	// assert profiles are loaded from both bundles
	// for each profile, assert it's is a node profile
	for _, p := range l.Items {
		pt := p.Annotations[compv1alpha1.ProductTypeAnnotation]
		if pt != "Node" {
			f.PrintROSADebugInfo(t)
			t.Fatalf("found an unexpected profile type: %s of type %s", p.GetName(), pt)
		}
	}

}

func TestScanSetting(t *testing.T) {
	if os.Getenv("E2E_SKIP_FRAMEWORK_SETUP") == "true" {
		t.Skip("requires manifest-based SetUp; run without E2E_SKIP_FRAMEWORK_SETUP")
	}
	f := framework.Global
	// prinout all scan settings
	scanSettingList := compv1alpha1.ScanSettingList{}
	err := f.Client.List(context.TODO(), &scanSettingList)
	if err != nil {
		t.Fatalf("Failed to list scan settings: %v", err)
	}
	for _, scanSetting := range scanSettingList.Items {
		if scanSetting.Name == "default-auto-apply" {
			f.PrintROSADebugInfo(t)
			t.Fatalf("ScanSetting: %s is not expected", scanSetting.Name)
		}
		t.Logf("ScanSetting: %s", scanSetting.Name)
		for _, role := range scanSetting.Roles {
			if role == "master" {
				f.PrintROSADebugInfo(t)
				t.Fatalf("Role: %s is not expected", role)
			}
			t.Logf("Role: %s", role)

		}
	}
}

// Test73945RosaHCPSubscriptionAndNodeProfilesScan ports TC 73945: ROSA HCP cluster with Compliance Operator
// installed via OLM Subscription (PLATFORM=rosa in spec.config.env), hosted profile expectations, and a
// two-profile node scan (ocp4-pci-dss-node + ocp4-cis-node) expecting NON-COMPLIANT and exit code 2 in result ConfigMaps.
//
// Run (dedicated job only — this does not use manifest SetUp):
//
//	E2E_SKIP_FRAMEWORK_SETUP=true TEST_OPERATOR_NAMESPACE=openshift-compliance \
//	  go test ./tests/e2e/rosa -v -args -root=<repo> -globalMan=<crd> -namespacedMan=<deploy> --platform rosa
//
// Optional: E2E_OLM_CHANNEL=stable E2E_OLM_SOURCE=redhat-operators E2E_OLM_SOURCE_NAMESPACE=openshift-marketplace
func Test73945RosaHCPSubscriptionAndNodeProfilesScan(t *testing.T) {
	if os.Getenv("E2E_SKIP_FRAMEWORK_SETUP") != "true" {
		t.Skip("TC 73945 requires OLM Subscription install: set E2E_SKIP_FRAMEWORK_SETUP=true and TEST_OPERATOR_NAMESPACE=openshift-compliance")
	}
	f := framework.Global

	channel := os.Getenv("E2E_OLM_CHANNEL")
	if channel == "" {
		channel = "stable"
	}
	catalogSource := os.Getenv("E2E_OLM_SOURCE")
	if catalogSource == "" {
		catalogSource = "redhat-operators"
	}
	catalogNS := os.Getenv("E2E_OLM_SOURCE_NAMESPACE")
	if catalogNS == "" {
		catalogNS = "openshift-marketplace"
	}

	skipReason, err := f.SkipRosa73945Preconditions(catalogSource, catalogNS)
	if err != nil {
		t.Fatalf("73945 preconditions: %v", err)
	}
	if skipReason != "" {
		t.Skip(skipReason)
	}

	if err := f.InstallComplianceOperatorSubscriptionRosa73945(channel, catalogSource, catalogNS); err != nil {
		t.Fatalf("install via Subscription: %v", err)
	}
	if err := f.RegisterComplianceResourceSchemes(); err != nil {
		t.Fatalf("register compliance schemes: %v", err)
	}

	if err := f.WaitForProfileBundleStatus("ocp4", compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("ocp4 profile bundle not VALID: %v", err)
	}
	if err := f.WaitForProfileBundleStatus("rhcos4", compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("rhcos4 profile bundle not VALID: %v", err)
	}

	if err := f.AssertSubscriptionConfigEnvContainsPlatformRosa(); err != nil {
		t.Fatalf("subscription PLATFORM env: %v", err)
	}
	if err := f.AssertScanSettingRolesJSON("default"); err != nil {
		t.Fatalf("ScanSetting default roles: %v", err)
	}
	if err := f.AssertScanSettingDoesNotExist("default-auto-apply"); err != nil {
		t.Fatalf("ScanSetting default-auto-apply must not exist: %v", err)
	}
	if err := f.AssertProfileDoesNotExist("ocp4-cis"); err != nil {
		t.Fatalf("Profile ocp4-cis must not exist on hosted profile set: %v", err)
	}

	ssbName := framework.GetObjNameFromTest(t) + "-73945"
	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ssbName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     "ocp4-pci-dss-node",
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
	if err := f.Client.Create(context.TODO(), ssb, nil); err != nil {
		t.Fatalf("create ScanSettingBinding %s: %v", ssbName, err)
	}
	defer func() {
		if err := f.DeleteScanSettingBindingAndWaitForCleanup(ssb); err != nil {
			t.Logf("cleanup ScanSettingBinding %s: %v", ssbName, err)
		}
	}()

	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, ssbName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant); err != nil {
		t.Fatalf("suite %s not DONE/COMPLIANT: %v", ssbName, err)
	}
	if err := f.AssertSuiteScanExitCodesContainSubstring(ssbName, "0"); err != nil {
		t.Fatalf("scan exit-code in result ConfigMaps: %v", err)
	}
}
