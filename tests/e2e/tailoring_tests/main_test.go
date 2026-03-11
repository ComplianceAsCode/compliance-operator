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
	corev1 "k8s.io/api/core/v1"
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
		t.Fatal(err)
	}
	for _, expected := range []string{
		"\"xccdf_org.ssgproject.content_rule_no_netrc_files\" selected=\"true\"",
		"\"xccdf_org.ssgproject.content_rule_audit_rules_dac_modification_chmod\" selected=\"false\"",
		"\"xccdf_org.ssgproject.content_value_var_selinux_state\">permissive",
	} {
		if !strings.Contains(tailoringData, expected) {
			t.Fatal(err)
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
		t.Fatalf("Expected the tailored profile to have a warning message but got none")
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

