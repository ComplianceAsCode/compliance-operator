package tailoring_e2e

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	configv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var brokenContentImagePath string
var contentImagePath string
var criticalOnly = flag.Bool("critical", false, "run ONLY critical tests")

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

// TestScanTailoredProfileIsDeprecated verifies deprecated profile warnings surface when a TP extends a deprecated profile.
// Critical: deprecation lifecycle and user visibility.
func TestScanTailoredProfileIsDeprecated(t *testing.T) {
	t.Parallel()
	f := framework.Global

	tpName := "test-tailored-profile-is-deprecated"
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
			Annotations: map[string]string{
				compv1alpha1.ProfileStatusAnnotation: "deprecated",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Extends:     "ocp4-cis",
			Title:       "TestScanTailoredProfileIsDeprecated",
			Description: "TestScanTailoredProfileIsDeprecated",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-cluster-version-operator-exists",
					Rationale: "Test tailored profile extends deprecated",
				},
			},
		},
	}
	err := f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	suiteName := framework.GetObjNameFromTest(t)
	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
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
			Name:     "default",
		},
	}
	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// When using SSB with TailoredProfile, the scan has same name as the TP
	scanName := tpName
	if err = f.WaitForProfileDeprecatedWarning(t, scanName, tpName); err != nil {
		t.Fatal(err)
	}

	if err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone); err != nil {
		t.Fatal(err)
	}
}

// TestScanTailoredProfileHasDuplicateVariables verifies duplicate variable setValues produce a validation warning.
// Important: TP validation; does not run a full scan.
func TestScanTailoredProfileHasDuplicateVariables(t *testing.T) {
	if *criticalOnly {
		t.Skip("Skipping non-critical test")
	}

	t.Parallel()
	f := framework.Global
	pbName := framework.GetObjNameFromTest(t)
	prefixName := func(profName, ruleBaseName string) string { return profName + "-" + ruleBaseName }
	varName := prefixName(pbName, "var-openshift-audit-profile")
	tpName := "test-tailored-profile-has-duplicate-variables"
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Extends:     "ocp4-cis",
			Title:       "TestScanTailoredProfileIsDuplicateVariables",
			Description: "TestScanTailoredProfileIsDuplicateVariables",
			SetValues: []compv1alpha1.VariableValueSpec{
				{
					Name:      varName,
					Rationale: "Value to be set",
					Value:     "WriteRequestBodies",
				},
				{
					Name:      varName,
					Rationale: "Value to be set",
					Value:     "SomethingElse",
				},
			},
		},
	}
	err := f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tp)
	// let's check if the profile is created and if event warning is being generated
	if err = f.WaitForDuplicatedVariableWarning(t, tpName, varName); err != nil {
		t.Fatal(err)
	}

}

// TestSingleTailoredScanSucceeds runs the full tailored-scan path: TP (enable/disable rules + SetValues) -> ConfigMap -> SSB -> scans complete and are Compliant.
// CRITICAL: core happy path for profile tailoring; if this fails, users cannot run tailored scans.
func TestSingleTailoredScanSucceeds(t *testing.T) {
	t.Parallel()
	f := framework.Global

	tpName := "test-tailoredprofile"
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
			Annotations: map[string]string{
				compv1alpha1.ProductTypeAnnotation: "Node",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "TestSingleTailoredScanSucceeds",
			Description: "TestSingleTailoredScanSucceeds",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "rhcos4-no-netrc-files",
					Rationale: "Test for platform profile tailoring",
				},
			},
			DisableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "rhcos4-audit-rules-dac-modification-chmod",
					Rationale: "Disable rule for testing",
				},
			},
			SetValues: []compv1alpha1.VariableValueSpec{
				{
					Name:      "rhcos4-var-selinux-state",
					Rationale: "Set variable value for testing",
					Value:     "permissive",
				},
			},
		},
	}
	err := f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the tailored profile details through ConfigMap
	tpConfigMapName := fmt.Sprintf("%s-tp", tpName)
	tpConfigMap := &corev1.ConfigMap{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{
		Name:      tpConfigMapName,
		Namespace: f.OperatorNamespace,
	}, tpConfigMap)
	if err != nil {
		t.Fatal(err)
	}

	tailoringData, ok := tpConfigMap.Data["tailoring.xml"]
	if !ok {
		t.Fatal("tailoring.xml not found in ConfigMap")
	}
	for _, expected := range []string{
		"\"xccdf_org.ssgproject.content_rule_no_netrc_files\" selected=\"true\"",
		"\"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_chmod\" selected=\"false\"",
		"\"xccdf_org.ssgproject.content_value_var_selinux_state\">permissive",
	} {
		if !strings.Contains(tailoringData, expected) {
			t.Fatalf("tailoring data missing expected content: %q", expected)
		}
	}

	suiteName := framework.GetObjNameFromTest(t)
	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
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
			Name:     "default",
		},
	}
	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// When using SSB with TailoredProfile, the scan has same name as the TP
	scanNameMaster := fmt.Sprintf("%s-master", tpName)
	scanNameWorker := fmt.Sprintf("%s-worker", tpName)
	if err = f.WaitForScanStatus(f.OperatorNamespace, scanNameMaster, compv1alpha1.PhaseDone); err != nil {
		t.Fatal(err)
	}
	if err = f.AssertScanIsCompliant(scanNameMaster, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}
	if err = f.WaitForScanStatus(f.OperatorNamespace, scanNameWorker, compv1alpha1.PhaseDone); err != nil {
		t.Fatal(err)
	}
	if err = f.AssertScanIsCompliant(scanNameWorker, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}
}

// TestScanSettingBindingTailoringManyEnablingRulePass verifies rule pruning when ProfileBundle content changes (e.g. rule type Platform->Node) and prune annotation behavior.
// Important: content-update and migration scenario; more specialized than the core scan path.
func TestScanSettingBindingTailoringManyEnablingRulePass(t *testing.T) {
	if *criticalOnly {
		t.Skip("Skipping non-critical test")
	}
	t.Parallel()
	f := framework.Global
	const (
		changeTypeRule      = "kubelet-anonymous-auth"
		unChangedTypeRule   = "api-server-insecure-port"
		moderateProfileName = "moderate"
		tpMixName           = "many-migrated-mix-tp"
		tpSingleName        = "migrated-single-tp"
		tpSingleNoPruneName = "migrated-single-no-prune-tp"
	)
	var (
		baselineImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "kubelet_default")
		modifiedImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "new_kubeletconfig")
	)

	prefixName := func(profName, ruleBaseName string) string { return profName + "-" + ruleBaseName }

	pbName := framework.GetObjNameFromTest(t)
	origPb, err := f.CreateProfileBundle(pbName, baselineImage, framework.OcpContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle: %s", err)
	}
	defer f.Client.Delete(context.TODO(), origPb)

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("failed waiting for the ProfileBundle to become available: %s", err)
	}

	changeTypeRuleName := prefixName(pbName, changeTypeRule)
	err, found := f.DoesRuleExist(origPb.Namespace, changeTypeRuleName)
	if err != nil {
		t.Fatal(err)
	} else if found != true {
		t.Fatalf("expected rule %s to exist in namespace %s", changeTypeRuleName, origPb.Namespace)
	}
	if err := f.AssertRuleIsPlatformType(changeTypeRuleName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}

	unChangedTypeRuleName := prefixName(pbName, unChangedTypeRule)
	err, found = f.DoesRuleExist(origPb.Namespace, unChangedTypeRuleName)
	if err != nil {
		t.Fatal(err)
	} else if found != true {
		t.Fatalf("expected rule %s to exist in namespace %s", unChangedTypeRuleName, origPb.Namespace)
	}
	if err := f.AssertRuleIsPlatformType(unChangedTypeRuleName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}

	tpMix := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpMixName,
			Namespace: f.OperatorNamespace,
			Annotations: map[string]string{
				compv1alpha1.PruneOutdatedReferencesAnnotationKey: "true",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "TestForManyRules",
			Description: "TestForManyRules",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{Name: changeTypeRuleName, Rationale: "this rule should be removed from the profile"},
				{Name: unChangedTypeRuleName, Rationale: "this rule should not be removed from the profile"},
			},
		},
	}

	tpSingle := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpSingleName,
			Namespace: f.OperatorNamespace,
			Annotations: map[string]string{
				compv1alpha1.PruneOutdatedReferencesAnnotationKey: "true",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "TestForManyRules",
			Description: "TestForManyRules",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{Name: changeTypeRuleName, Rationale: "this rule should be removed from the profile"},
			},
		},
	}

	tpMixNoPrune := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpSingleNoPruneName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "TestForNoPrune",
			Description: "TestForNoPrune",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{Name: changeTypeRuleName, Rationale: "this rule should not be removed from the profile"},
				{Name: unChangedTypeRuleName, Rationale: "this rule should not be removed from the profile"},
			},
		},
	}

	if err := f.Client.Create(context.TODO(), tpMix, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tpMix)
	if err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpMixName, compv1alpha1.TailoredProfileStateReady); err != nil {
		t.Fatal(err)
	}
	hasRule, err := f.EnableRuleExistInTailoredProfile(f.OperatorNamespace, tpMixName, changeTypeRuleName)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule {
		t.Fatalf("Expected the tailored profile to have rule: %s", changeTypeRuleName)
	}
	hasRule, err = f.EnableRuleExistInTailoredProfile(f.OperatorNamespace, tpMixName, unChangedTypeRuleName)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule {
		t.Fatalf("Expected the tailored profile to have rule: %s", unChangedTypeRuleName)
	}

	if err := f.Client.Create(context.TODO(), tpSingle, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tpSingle)
	if err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpSingleName, compv1alpha1.TailoredProfileStateReady); err != nil {
		t.Fatal(err)
	}
	hasRule, err = f.EnableRuleExistInTailoredProfile(f.OperatorNamespace, tpSingleName, changeTypeRuleName)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule {
		t.Fatalf("Expected the tailored profile to have rule: %s", changeTypeRuleName)
	}

	if err := f.Client.Create(context.TODO(), tpMixNoPrune, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tpMixNoPrune)
	if err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpSingleNoPruneName, compv1alpha1.TailoredProfileStateReady); err != nil {
		t.Fatal(err)
	}
	hasRule, err = f.EnableRuleExistInTailoredProfile(f.OperatorNamespace, tpSingleNoPruneName, changeTypeRuleName)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule {
		t.Fatalf("Expected the tailored profile to have rule: %s", changeTypeRuleName)
	}

	modPb := origPb.DeepCopy()
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: modPb.Namespace, Name: modPb.Name}, modPb); err != nil {
		t.Fatalf("failed to get ProfileBundle %s", modPb.Name)
	}
	modPb.Spec.ContentImage = modifiedImage
	if err := f.Client.Update(context.TODO(), modPb); err != nil {
		t.Fatalf("failed to update ProfileBundle %s: %s", modPb.Name, err)
	}
	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("failed to parse ProfileBundle %s: %s", pbName, err)
	}
	if err := f.AssertProfileBundleMustHaveParsedRules(pbName); err != nil {
		t.Fatal(err)
	}
	if err := f.AssertRuleIsPlatformType(unChangedTypeRuleName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}
	if err := f.AssertRuleIsNodeType(changeTypeRuleName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}
	if err := f.AssertRuleCheckTypeChangedAnnotationKey(f.OperatorNamespace, changeTypeRuleName, "Platform"); err != nil {
		t.Fatal(err)
	}

	if err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpMixName, compv1alpha1.TailoredProfileStateReady); err != nil {
		t.Fatal(err)
	}
	hasRule, err = f.EnableRuleExistInTailoredProfile(f.OperatorNamespace, tpMixName, changeTypeRuleName)
	if err != nil {
		t.Fatal(err)
	}
	if hasRule {
		t.Fatal("Expected the tailored profile to not have the rule")
	}
	hasRule, err = f.EnableRuleExistInTailoredProfile(f.OperatorNamespace, tpMixName, unChangedTypeRuleName)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule {
		t.Fatalf("Expected the tailored profile to have rule: %s", unChangedTypeRuleName)
	}

	if err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpSingleName, compv1alpha1.TailoredProfileStateError); err != nil {
		t.Fatal(err)
	}
	hasRule, err = f.EnableRuleExistInTailoredProfile(f.OperatorNamespace, tpSingleName, changeTypeRuleName)
	if err != nil {
		t.Fatal(err)
	}
	if hasRule {
		t.Fatalf("Expected the tailored profile not to have rule: %s", changeTypeRuleName)
	}

	if err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpSingleNoPruneName, compv1alpha1.TailoredProfileStateReady); err != nil {
		t.Fatal(err)
	}
	hasRule, err = f.EnableRuleExistInTailoredProfile(f.OperatorNamespace, tpSingleNoPruneName, changeTypeRuleName)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule {
		t.Fatalf("Expected the tailored profile to have rule: %s", changeTypeRuleName)
	}

	tpSingleNoPruneFetched := &compv1alpha1.TailoredProfile{}
	key := types.NamespacedName{Namespace: f.OperatorNamespace, Name: tpSingleNoPruneName}
	if err := f.Client.Get(context.Background(), key, tpSingleNoPruneFetched); err != nil {
		t.Fatal(err)
	}
	if len(tpSingleNoPruneFetched.Status.Warnings) == 0 {
		t.Fatal("Expected the tailored profile to have a warning message but got none")
	}
	if !strings.Contains(tpSingleNoPruneFetched.Status.Warnings, changeTypeRule) {
		t.Fatalf("Expected the tailored profile to have a warning message about migrated rule: %s but got: %s", changeTypeRule, tpSingleNoPruneFetched.Status.Warnings)
	}

	tpSingleNoPruneFetchedCopy := tpSingleNoPruneFetched.DeepCopy()
	tpSingleNoPruneFetchedCopy.Annotations[compv1alpha1.PruneOutdatedReferencesAnnotationKey] = "true"
	if err := f.Client.Update(context.Background(), tpSingleNoPruneFetchedCopy); err != nil {
		t.Fatal(err)
	}
	if err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpSingleNoPruneName, compv1alpha1.TailoredProfileStateReady); err != nil {
		t.Fatal(err)
	}
	tpSingleNoPruneNoWarning := &compv1alpha1.TailoredProfile{}
	if err := f.Client.Get(context.Background(), key, tpSingleNoPruneNoWarning); err != nil {
		t.Fatal(err)
	}
	if len(tpSingleNoPruneNoWarning.Status.Warnings) != 0 {
		t.Fatalf("Expected the tailored profile to have no warning message but got: %s", tpSingleNoPruneNoWarning.Status.Warnings)
	}
	hasRule, err = f.EnableRuleExistInTailoredProfile(f.OperatorNamespace, tpSingleNoPruneName, changeTypeRuleName)
	if err != nil {
		t.Fatal(err)
	}
	if hasRule {
		t.Fatalf("Expected the tailored profile not to have rule: %s", changeTypeRuleName)
	}
}

// TestScanSettingBindingWatchesTailoredProfile verifies SSB reflects TP status: invalid TP -> binding Ready=False/Invalid; fix TP -> binding becomes Ready.
// CRITICAL: SSB must watch TP and not start suites when the referenced TailoredProfile is invalid.
func TestScanSettingBindingWatchesTailoredProfile(t *testing.T) {
	t.Parallel()
	f := framework.Global
	tpName := framework.GetObjNameFromTest(t)
	bindingName := framework.GetObjNameFromTest(t)

	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "TestScanSettingBindingWatchesTailoredProfile",
			Description: "TestScanSettingBindingWatchesTailoredProfile",
			DisableRules: []compv1alpha1.RuleReferenceSpec{
				{Name: "no-such-rule", Rationale: "testing"},
			},
			Extends: "ocp4-cis",
		},
	}
	if err := f.Client.Create(context.TODO(), tp, nil); err != nil {
		t.Fatal("failed to create tailored profile")
	}
	defer f.Client.Delete(context.TODO(), tp)

	err := wait.Poll(framework.RetryInterval, framework.Timeout, func() (bool, error) {
		tpGet := &compv1alpha1.TailoredProfile{}
		if getErr := f.Client.Get(context.TODO(), types.NamespacedName{Name: tpName, Namespace: f.OperatorNamespace}, tpGet); getErr != nil {
			return false, nil
		}
		if tpGet.Status.State != compv1alpha1.TailoredProfileStateError {
			return false, errors.New("expected the TP to be created with an error")
		}
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	scanSettingBinding := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{Name: bindingName, Kind: "TailoredProfile", APIGroup: "compliance.openshift.io/v1alpha1"},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			Name: "default", Kind: "ScanSetting", APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}
	if err := f.Client.Create(context.TODO(), &scanSettingBinding, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSettingBinding)

	err = wait.Poll(framework.RetryInterval, framework.Timeout, func() (bool, error) {
		ssbGet := &compv1alpha1.ScanSettingBinding{}
		if getErr := f.Client.Get(context.TODO(), types.NamespacedName{Name: bindingName, Namespace: f.OperatorNamespace}, ssbGet); getErr != nil {
			return false, nil
		}
		readyCond := ssbGet.Status.Conditions.GetCondition("Ready")
		if readyCond == nil {
			return false, nil
		}
		if readyCond.Status != corev1.ConditionFalse && readyCond.Reason != "Invalid" {
			return false, fmt.Errorf("expected ready=false, reason=invalid, got %v", readyCond)
		}
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	tpGet := &compv1alpha1.TailoredProfile{}
	if err = f.Client.Get(context.TODO(), types.NamespacedName{Name: tpName, Namespace: f.OperatorNamespace}, tpGet); err != nil {
		t.Fatal(err)
	}
	tpUpdate := tpGet.DeepCopy()
	tpUpdate.Spec.DisableRules = []compv1alpha1.RuleReferenceSpec{
		{Name: "ocp4-file-owner-scheduler-kubeconfig", Rationale: "testing"},
	}
	if err = f.Client.Update(context.TODO(), tpUpdate); err != nil {
		t.Fatal(err)
	}

	err = wait.Poll(framework.RetryInterval, framework.Timeout, func() (bool, error) {
		ssbGet := &compv1alpha1.ScanSettingBinding{}
		if getErr := f.Client.Get(context.TODO(), types.NamespacedName{Name: bindingName, Namespace: f.OperatorNamespace}, ssbGet); getErr != nil {
			return false, nil
		}
		readyCond := ssbGet.Status.Conditions.GetCondition("Ready")
		if readyCond == nil {
			return false, nil
		}
		if readyCond.Status != corev1.ConditionTrue && readyCond.Reason != "Processed" {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestManualRulesTailoredProfile verifies ManualRules result in CheckResultManual and no remediations.
// CRITICAL: manual vs automatic remediation semantics are a core tailoring feature.
func TestManualRulesTailoredProfile(t *testing.T) {
	t.Parallel()
	f := framework.Global
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
	requiredRuleName := prefixName(pbName, requiredRule)
	err, found := framework.Global.DoesRuleExist(f.OperatorNamespace, requiredRuleName)
	if err != nil {
		t.Fatal(err)
	} else if !found {
		t.Fatalf("Expected rule %s not found", requiredRuleName)
	}

	suiteName := "manual-rules-test-node"
	masterScanName := fmt.Sprintf("%s-master", suiteName)
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
			Annotations: map[string]string{
				compv1alpha1.DisableOutdatedReferenceValidation: "true",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "manual-rules-test",
			Description: "A test tailored profile to test manual-rules",
			ManualRules: []compv1alpha1.RuleReferenceSpec{
				{Name: prefixName(pbName, requiredRule), Rationale: "To be tested"},
			},
		},
	}
	if err := f.Client.Create(context.TODO(), tp, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{APIGroup: "compliance.openshift.io/v1alpha1", Kind: "TailoredProfile", Name: suiteName},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1", Kind: "ScanSetting", Name: "default",
		},
	}
	if err = f.Client.Create(context.TODO(), ssb, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	if err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}
	checkResult := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-kubelet-eviction-thresholds-set-soft-imagefs-available", masterScanName),
			Namespace: f.OperatorNamespace,
		},
		ID:       "xccdf_org.ssgproject.content_rule_kubelet_eviction_thresholds_set_soft_imagefs_available",
		Status:   compv1alpha1.CheckResultManual,
		Severity: compv1alpha1.CheckResultSeverityMedium,
	}
	if err = f.AssertHasCheck(suiteName, masterScanName, checkResult); err != nil {
		t.Fatal(err)
	}
	inNs := client.InNamespace(f.OperatorNamespace)
	withLabel := client.MatchingLabels{"profile-bundle": pbName}
	remList := &compv1alpha1.ComplianceRemediationList{}
	if err = f.Client.List(context.TODO(), remList, inNs, withLabel); err != nil {
		t.Fatal(err)
	}
	if len(remList.Items) != 0 {
		t.Fatal("expected no remediation")
	}
}

// TestHideRule verifies hidden rules do not appear in scan results (NoResult).
// Important: hide vs enable is a common tailoring operation.
func TestHideRule(t *testing.T) {
	if *criticalOnly {
		t.Skip("Skipping non-critical test")
	}
	t.Parallel()
	f := framework.Global
	var baselineImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "hide_rule")
	const requiredRule = "version-detect"
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
	requiredRuleName := prefixName(pbName, requiredRule)
	err, found := f.DoesRuleExist(ocpPb.Namespace, requiredRuleName)
	if err != nil {
		t.Fatal(err)
	} else if !found {
		t.Fatalf("Expected rule %s not found", requiredRuleName)
	}

	suiteName := "hide-rules-test"
	scanName := "hide-rules-test"
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "hide-rules-test",
			Description: "A test tailored profile to test hide-rules",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{Name: prefixName(pbName, requiredRule), Rationale: "To be tested"},
			},
		},
	}
	if err := f.Client.Create(context.TODO(), tp, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{APIGroup: "compliance.openshift.io/v1alpha1", Kind: "TailoredProfile", Name: suiteName},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1", Kind: "ScanSetting", Name: "default",
		},
	}
	if err = f.Client.Create(context.TODO(), ssb, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	if err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNotApplicable); err != nil {
		t.Fatal(err)
	}
	checkResult := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-version-detect", scanName),
			Namespace: f.OperatorNamespace,
		},
		ID:       "xccdf_org.ssgproject.content_rule_version_detect",
		Status:   compv1alpha1.CheckResultNoResult,
		Severity: compv1alpha1.CheckResultSeverityMedium,
	}
	if err = f.AssertHasCheck(suiteName, scanName, checkResult); err == nil {
		t.Fatalf("The check should not be found in the scan %s", scanName)
	}
}

func TestScanTailoredProfileExtendsDeprecated(t *testing.T) {
	t.Parallel()
	f := framework.Global

	pbName := framework.GetObjNameFromTest(t)
	baselineImage := fmt.Sprintf("%s:%s", brokenContentImagePath, "deprecated_profile")
	pb, err := f.CreateProfileBundle(pbName, baselineImage, framework.OcpContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle: %s", err)
	}
	// This should get cleaned up at the end of the test
	defer f.Client.Delete(context.TODO(), pb)

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("failed waiting for the ProfileBundle to become available: %s", err)
	}

	tpName := "test-tailored-profile-extends-deprecated"
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Extends:     "ocp4-cis-1-4",
			Title:       "TestScanTailoredProfileExtendsDeprecated",
			Description: "TestScanTailoredProfileExtendsDeprecated",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-cluster-version-operator-exists",
					Rationale: "Test tailored profile extends deprecated",
				},
			},
		},
	}
	createTPErr := f.Client.Create(context.TODO(), tp, nil)
	if createTPErr != nil {
		t.Fatal(createTPErr)
	}
	defer f.Client.Delete(context.TODO(), tp)

	suiteName := framework.GetObjNameFromTest(t)
	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
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
			Name:     "default",
		},
	}
	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// When using SSB with TailoredProfile, the scan has same name as the TP
	scanName := tpName
	if err = f.WaitForProfileDeprecatedWarning(t, scanName, tpName); err != nil {
		t.Fatal(err)
	}

	if err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone); err != nil {
		t.Fatal(err)
	}
}
// TestTailoredProfileFromScratchPlatformOnly tests creating a TailoredProfile
// from scratch with only platform rules (no extends field).
func TestTailoredProfileFromScratchPlatformOnly(t *testing.T) {
	t.Parallel()
	f := framework.Global

	tpName := "test-tailoredplatformprofile"
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "Platform profile from scratch",
			Description: "Test platform profile created without extending",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-cluster-version-operator-exists",
					Rationale: "Test for platform profile tailoring",
				},
				{
					Name:      "ocp4-api-server-admission-control-plugin-alwaysadmit",
					Rationale: "Platform rule",
				},
			},
			DisableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-api-server-admission-control-plugin-alwayspullimages",
					Rationale: "Platform disable rule",
				},
			},
		},
	}
	err := f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatal(err)
	}
}

// TestTailoredProfileFromScratchNodeOnly tests creating a TailoredProfile
// from scratch with only node rules (no extends field).
func TestTailoredProfileFromScratchNodeOnly(t *testing.T) {
	t.Parallel()
	f := framework.Global

	tpName := "test-tailorednodeprofile"
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "Node profile from scratch",
			Description: "Test node profile created without extending",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-file-groupowner-cni-conf",
					Rationale: "Node rule",
				},
				{
					Name:      "ocp4-accounts-restrict-service-account-tokens",
					Rationale: "Node rule",
				},
			},
			DisableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-file-groupowner-etcd-data-dir",
					Rationale: "Node disable rule",
				},
			},
		},
	}
	err := f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatal(err)
	}
}

// TestTailoredProfileFromScratchMixedCheckTypesErrors tests that a TailoredProfile
// with both node and platform rules goes into ERROR state with the expected error message.
func TestTailoredProfileFromScratchMixedCheckTypesErrors(t *testing.T) {
	t.Parallel()
	f := framework.Global

	tpName := "test-tailoredmixedprofile"
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "Mixed profile from scratch",
			Description: "Test profile with both node and platform rules",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-file-groupowner-cni-conf",
					Rationale: "Node rule",
				},
				{
					Name:      "ocp4-api-server-admission-control-plugin-alwayspullimages",
					Rationale: "Platform rule",
				},
			},
			DisableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-file-groupowner-etcd-data-dir",
					Rationale: "Node disable rule",
				},
				{
					Name:      "ocp4-api-server-admission-control-plugin-alwaysadmit",
					Rationale: "Platform disable rule",
				},
			},
		},
	}
	err := f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	// Verify it goes to ERROR state
	err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpName, compv1alpha1.TailoredProfileStateError)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the error message contains expected text
	tpObj := &compv1alpha1.TailoredProfile{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: tpName, Namespace: f.OperatorNamespace}, tpObj)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tpObj.Status.ErrorMessage, "didn't match expected type") {
		t.Fatalf("Expected error message to contain 'didn't match expected type', got: %s", tpObj.Status.ErrorMessage)
	}
}

// TestTailoredProfilePatchFixesMixedCheckTypeError tests that patching a TailoredProfile
// with mixed checkTypes to remove conflicting rules moves it from ERROR to READY state.
func TestTailoredProfilePatchFixesMixedCheckTypeError(t *testing.T) {
	t.Parallel()
	f := framework.Global

	tpName := "test-tailoredmixedprofile-patch"
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "Mixed profile from scratch",
			Description: "Test profile with both node and platform rules",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-file-groupowner-cni-conf",
					Rationale: "Node rule",
				},
				{
					Name:      "ocp4-api-server-admission-control-plugin-alwayspullimages",
					Rationale: "Platform rule",
				},
			},
			DisableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-file-groupowner-etcd-data-dir",
					Rationale: "Node disable rule",
				},
				{
					Name:      "ocp4-api-server-admission-control-plugin-alwaysadmit",
					Rationale: "Platform disable rule",
				},
			},
		},
	}
	err := f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	// Wait for ERROR state
	err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpName, compv1alpha1.TailoredProfileStateError)
	if err != nil {
		t.Fatal(err)
	}

	// Patch to fix it by removing conflicting rules
	tpObj := &compv1alpha1.TailoredProfile{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: tpName, Namespace: f.OperatorNamespace}, tpObj)
	if err != nil {
		t.Fatal(err)
	}

	// Remove disableRules first
	patchRemoveDisable := []byte(`[{"op": "remove", "path": "/spec/disableRules"}]`)
	err = f.Client.Patch(context.TODO(), tpObj, client.RawPatch(types.JSONPatchType, patchRemoveDisable))
	if err != nil {
		t.Fatalf("Failed to patch TailoredProfile to remove disableRules: %s", err)
	}

	// Remove the first enableRule (node rule) to make it platform-only
	patchRemoveFirstEnable := []byte(`[{"op": "remove", "path": "/spec/enableRules/0"}]`)
	err = f.Client.Patch(context.TODO(), tpObj, client.RawPatch(types.JSONPatchType, patchRemoveFirstEnable))
	if err != nil {
		t.Fatalf("Failed to patch TailoredProfile to remove enableRules[0]: %s", err)
	}

	// Verify it becomes READY after patching
	err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatal(err)
	}
}

// TestTailoredProfileRequiresTitle tests that the title field is required
// when creating a TailoredProfile.
func TestTailoredProfileRequiresTitle(t *testing.T) {
	t.Parallel()
	f := framework.Global

	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-notitle",
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Description: "Profile without title",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-file-groupowner-cni-conf",
					Rationale: "Node rule",
				},
			},
		},
	}
	err := f.Client.Create(context.TODO(), tp, nil)
	if err == nil {
		f.Client.Delete(context.TODO(), tp)
		t.Fatal("Expected error when creating TailoredProfile without title, but got none")
	}
	if !strings.Contains(err.Error(), "spec.title") && !strings.Contains(err.Error(), "Required value") {
		t.Fatalf("Expected error about missing title, got: %s", err)
	}
}

// TestTailoredProfileRequiresDescription tests that the description field is required
// when creating a TailoredProfile.
func TestTailoredProfileRequiresDescription(t *testing.T) {
	t.Parallel()
	f := framework.Global

	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-nodesc",
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title: "Profile without description",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-file-groupowner-cni-conf",
					Rationale: "Node rule",
				},
			},
		},
	}
	err := f.Client.Create(context.TODO(), tp, nil)
	if err == nil {
		f.Client.Delete(context.TODO(), tp)
		t.Fatal("Expected error when creating TailoredProfile without description, but got none")
	}
	if !strings.Contains(err.Error(), "spec.description") && !strings.Contains(err.Error(), "Required value") {
		t.Fatalf("Expected error about missing description, got: %s", err)
	}
}

// TestTailoredProfileFromScratchPlatformScanSucceeds tests creating a platform
// TailoredProfile from scratch and running a successful compliance scan with it.
// Also validates proxy configuration if the cluster uses a proxy.
func TestTailoredProfileFromScratchPlatformScanSucceeds(t *testing.T) {
	t.Parallel()
	f := framework.Global

	// Check if cluster is proxy and verify deployment env vars if so
	var httpsProxy string
	proxy := &configv1.Proxy{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: "cluster"}, proxy); err == nil {
		httpsProxy = proxy.Spec.HTTPSProxy
		if httpsProxy != "" {
			deployment, err := f.KubeClient.AppsV1().Deployments(f.OperatorNamespace).Get(context.TODO(), "compliance-operator", metav1.GetOptions{})
			if err != nil {
				t.Fatalf("failed to get compliance-operator deployment: %s", err)
			}
			if len(deployment.Spec.Template.Spec.Containers) == 0 {
				t.Fatal("compliance-operator deployment has no containers")
			}

			envMap := make(map[string]string)
			for _, env := range deployment.Spec.Template.Spec.Containers[0].Env {
				if env.Name == "HTTPS_PROXY" {
					envMap[env.Name] = env.Value
				}
			}
			if httpsProxy != "" && envMap["HTTPS_PROXY"] != httpsProxy {
				t.Fatalf("HTTPS_PROXY mismatch. Expected: %s, Got: %s", httpsProxy, envMap["HTTPS_PROXY"])
			}
		}
	}

	tpName := "test-tailoredplatformprofile-scan"
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "Platform profile from scratch",
			Description: "Test platform profile created without extending",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-cluster-version-operator-exists",
					Rationale: "Test for platform profile tailoring",
				},
				{
					Name:      "ocp4-api-server-admission-control-plugin-alwaysadmit",
					Rationale: "Platform rule",
				},
			},
			DisableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-api-server-admission-control-plugin-alwayspullimages",
					Rationale: "Platform disable rule",
				},
			},
		},
	}
	err := f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatal(err)
	}

	suiteName := framework.GetObjNameFromTest(t)
	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
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
			Name:     "default",
		},
	}
	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// When using SSB with TailoredProfile, the scan has same name as the TP
	scanName := tpName
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanIsCompliant(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	// If proxy cluster, verify httpsProxy in configmap
	// CO only propagates and uses httpsProxy
	if httpsProxy != "" {
		cm := &corev1.ConfigMap{}
		cmName := scanName + "-openscap-env-map"
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: cmName, Namespace: f.OperatorNamespace}, cm); err != nil && apierrors.IsNotFound(err) {
			cmList := &corev1.ConfigMapList{}
			if err := f.Client.List(context.TODO(), cmList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels{
				compv1alpha1.ComplianceScanLabel: scanName,
				compv1alpha1.ScriptLabel:         "",
			}); err != nil {
				t.Fatalf("failed to list ConfigMaps: %s", err)
			}
			for i := range cmList.Items {
				if strings.Contains(cmList.Items[i].Name, "openscap-env-map") && cmList.Items[i].Data["HTTPS_PROXY"] != "" {
					cm = &cmList.Items[i]
					break
				}
			}
		} else if err != nil {
			t.Fatalf("failed to get ConfigMap: %s", err)
		}

		if cm.Data["HTTPS_PROXY"] != httpsProxy {
			t.Fatalf("HTTPS_PROXY mismatch in configmap. Expected: %s, Got: %s", httpsProxy, cm.Data["HTTPS_PROXY"])
		}
	}
}

// TestTailoredProfileFromScratchNodeScanSucceeds tests creating a node
// TailoredProfile from scratch and running a successful compliance scan with it.
func TestTailoredProfileFromScratchNodeScanSucceeds(t *testing.T) {
	t.Parallel()
	f := framework.Global

	tpName := "test-tailorednodeprofile-scan"
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "Node profile from scratch",
			Description: "Test node profile created without extending",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-file-groupowner-cni-conf",
					Rationale: "Node rule",
				},
				{
					Name:      "ocp4-accounts-restrict-service-account-tokens",
					Rationale: "Node rule",
				},
			},
			DisableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-file-groupowner-etcd-data-dir",
					Rationale: "Node disable rule",
				},
			},
		},
	}
	err := f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatal(err)
	}

	suiteName := framework.GetObjNameFromTest(t)
	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
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
			Name:     "default",
		},
	}
	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// When using SSB with TailoredProfile, the scan has same name as the TP
	scanName := tpName
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}
}
