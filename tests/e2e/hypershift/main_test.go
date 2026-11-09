package hypershift_e2e

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

func TestInstallOnlyParsesNodeProfiles(t *testing.T) {
	t.Parallel()
	f := framework.Global

	// list all profiles
	l := compv1alpha1.ProfileList{}
	err := f.Client.List(context.TODO(), &l)
	if err != nil {
		t.Fatalf("failed to get ProfileList: %s", err)
	}

	// HyperShift only exposes node profiles; assert each profile is a node profile
	for _, p := range l.Items {
		pt := p.Annotations[compv1alpha1.ProductTypeAnnotation]
		if pt != "Node" {
			t.Fatalf("found an unexpected profile type: %s of type %s", p.GetName(), pt)
		}
	}
}

func TestDefaultScanSettingsDoNotApplyRemediations(t *testing.T) {
	t.Parallel()
	f := framework.Global

	scanSettingList := compv1alpha1.ScanSettingList{}
	err := f.Client.List(context.TODO(), &scanSettingList)
	if err != nil {
		t.Fatalf("Failed to list scan settings: %v", err)
	}

	for _, scanSetting := range scanSettingList.Items {
		if scanSetting.AutoApplyRemediations {
			t.Fatalf("ScanSetting %s has AutoApplyRemediations enabled", scanSetting.Name)
		}
	}
}

func TestDefaultScanSettingsOnlyTargetWorkerPools(t *testing.T) {
	t.Parallel()
	f := framework.Global

	scanSettingList := compv1alpha1.ScanSettingList{}
	err := f.Client.List(context.TODO(), &scanSettingList)
	if err != nil {
		t.Fatalf("Failed to list scan settings: %v", err)
	}

	for _, scanSetting := range scanSettingList.Items {
		for _, role := range scanSetting.Roles {
			if role == "master" {
				t.Fatalf("ScanSetting %s contains unexpected master role", scanSetting.Name)
			}
		}
	}
}

func TestNodeScanCompletes(t *testing.T) {
	f := framework.Global

	ssbName := framework.GetObjNameFromTest(t) + "-hypershift"
	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ssbName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
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
}
