package parallel_e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils/celvalidation"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// TestCustomRuleVariableSetValues verifies CEL variable delivery (CMP-4550):
// a CustomRule references a Variable CR through its auto-derived CEL
// identifier (dashes become underscores), the value resolves at scan time, a
// TailoredProfile's setValues override the stored value per scan without
// mutating the Variable CR, and an expression referencing a variable that
// does not exist is rejected at admission.
func TestCustomRuleVariableSetValues(t *testing.T) {
	t.Parallel()
	f := framework.Global

	testName := framework.GetObjNameFromTest(t)
	varName := fmt.Sprintf("%s-var-max-cm", testName)
	derivedIdent, ok := celvalidation.DeriveCelIdentifier(varName)
	if !ok {
		t.Fatalf("Variable name %q must derive to a CEL identifier", varName)
	}
	customRuleName := fmt.Sprintf("%s-budget", testName)
	badRuleName := fmt.Sprintf("%s-undeclared", testName)
	tpName := fmt.Sprintf("%s-tp", testName)
	ssbName := fmt.Sprintf("%s-ssb", testName)
	testNamespace := f.OperatorNamespace

	// A Variable with a deliberately dash-separated name; the CustomRule
	// references it as derivedIdent. The stored value is far above any
	// realistic ConfigMap count, so the first scan passes.
	variable := &compv1alpha1.Variable{
		ObjectMeta: metav1.ObjectMeta{
			Name:      varName,
			Namespace: testNamespace,
		},
		VariablePayload: compv1alpha1.VariablePayload{
			ID:    strings.ReplaceAll(varName, "-", "_"),
			Title: "Maximum allowed ConfigMaps",
			Type:  compv1alpha1.VarTypeNumber,
			Value: "100000",
		},
	}
	if err := f.Client.Create(context.TODO(), variable, nil); err != nil {
		t.Fatalf("Failed to create Variable: %v", err)
	}
	defer f.Client.Delete(context.TODO(), variable)

	customRule := &compv1alpha1.CustomRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      customRuleName,
			Namespace: testNamespace,
		},
		Spec: compv1alpha1.CustomRuleSpec{
			RulePayload: compv1alpha1.RulePayload{
				ID:          customRuleName,
				Title:       "ConfigMap count stays under the tailored budget",
				Description: "Compares the ConfigMap count against the Variable-provided budget",
				Severity:    "medium",
				ScannerType: compv1alpha1.ScannerTypeCEL,
				Expression:  fmt.Sprintf(`cms.items.size() <= int(%s)`, derivedIdent),
				Inputs: []compv1alpha1.InputPayload{
					{
						Name: "cms",
						KubernetesInputSpec: compv1alpha1.KubernetesInputSpec{
							APIVersion:        "v1",
							Resource:          "configmaps",
							ResourceNamespace: testNamespace,
						},
					},
				},
				FailureReason: "The number of ConfigMaps exceeds the budget set through the Variable",
			},
		},
	}
	if err := f.Client.Create(context.TODO(), customRule, nil); err != nil {
		t.Fatalf("Failed to create CustomRule: %v", err)
	}
	defer f.Client.Delete(context.TODO(), customRule)

	if err := f.WaitForCustomRuleStatus(testNamespace, customRuleName, "Ready"); err != nil {
		t.Fatalf("CustomRule referencing the derived variable identifier did not become Ready: %v", err)
	}

	// Negative admission: an expression referencing a variable identifier
	// with no backing Variable CR must be rejected.
	badRule := customRule.DeepCopy()
	badRule.ObjectMeta = metav1.ObjectMeta{Name: badRuleName, Namespace: testNamespace}
	badRule.Spec.ID = badRuleName
	badRule.Spec.Expression = `cms.items.size() <= int(no_such_variable_xyz)`
	if err := f.Client.Create(context.TODO(), badRule, nil); err != nil {
		t.Fatalf("Failed to create negative CustomRule: %v", err)
	}
	defer f.Client.Delete(context.TODO(), badRule)

	if err := f.WaitForCustomRuleStatus(testNamespace, badRuleName, "Error"); err != nil {
		t.Fatalf("CustomRule referencing an unknown variable must be rejected: %v", err)
	}

	// Ordering: a rule created before its Variable is rejected, then
	// revalidated automatically once the Variable appears (Variable watch).
	lateVarName := fmt.Sprintf("%s-var-late", testName)
	lateRuleName := fmt.Sprintf("%s-late", testName)
	lateRule := customRule.DeepCopy()
	lateRule.ObjectMeta = metav1.ObjectMeta{Name: lateRuleName, Namespace: testNamespace}
	lateRule.Spec.ID = lateRuleName
	lateIdent, ok := celvalidation.DeriveCelIdentifier(lateVarName)
	if !ok {
		t.Fatalf("Variable name %q must derive to a CEL identifier", lateVarName)
	}
	lateRule.Spec.Expression = fmt.Sprintf(`cms.items.size() >= int(%s)`, lateIdent)
	if err := f.Client.Create(context.TODO(), lateRule, nil); err != nil {
		t.Fatalf("Failed to create late-variable CustomRule: %v", err)
	}
	defer f.Client.Delete(context.TODO(), lateRule)
	if err := f.WaitForCustomRuleStatus(testNamespace, lateRuleName, "Error"); err != nil {
		t.Fatalf("CustomRule must be rejected while its Variable does not exist: %v", err)
	}
	lateVar := variable.DeepCopy()
	lateVar.ObjectMeta = metav1.ObjectMeta{Name: lateVarName, Namespace: testNamespace}
	lateVar.ID = strings.ReplaceAll(lateVarName, "-", "_")
	lateVar.Value = "0"
	if err := f.Client.Create(context.TODO(), lateVar, nil); err != nil {
		t.Fatalf("Failed to create late Variable: %v", err)
	}
	defer f.Client.Delete(context.TODO(), lateVar)
	if err := f.WaitForCustomRuleStatus(testNamespace, lateRuleName, "Ready"); err != nil {
		t.Fatalf("CustomRule must become Ready once its Variable appears: %v", err)
	}

	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: testNamespace,
			Annotations: map[string]string{
				compv1alpha1.DisableOutdatedReferenceValidation: "true",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "CEL variable delivery",
			Description: "Exercises Variable resolution and setValues override for CEL CustomRules",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      customRuleName,
					Kind:      "CustomRule",
					Rationale: "Verify Variable values reach CEL expressions",
				},
			},
		},
	}
	if err := f.Client.Create(context.TODO(), tp, nil); err != nil {
		t.Fatalf("Failed to create TailoredProfile: %v", err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ssbName,
			Namespace: testNamespace,
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
	if err := f.Client.Create(context.TODO(), ssb, nil); err != nil {
		t.Fatalf("Failed to create ScanSettingBinding: %v", err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	suiteName := ssbName
	scanName := tpName

	// With the stored value (100000) the budget rule passes.
	if err := f.WaitForSuiteScansStatus(testNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant); err != nil {
		t.Fatalf("Scan with the stored Variable value did not pass: %v", err)
	}
	passCheck := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", scanName, customRuleName),
			Namespace: testNamespace,
		},
		ID:     customRuleName,
		Status: compv1alpha1.CheckResultPass,
	}
	if err := f.AssertHasCheck(suiteName, scanName, passCheck); err != nil {
		t.Fatalf("Expected PASS with the stored Variable value: %v", err)
	}

	// Tailor the value down to 0 via setValues; the same rule must now fail,
	// while the Variable CR itself stays untouched.
	tpKey := types.NamespacedName{Name: tpName, Namespace: testNamespace}
	if err := f.Client.Get(context.TODO(), tpKey, tp); err != nil {
		t.Fatal(err)
	}
	tp.Spec.SetValues = []compv1alpha1.VariableValueSpec{
		{
			Name:      varName,
			Value:     "0",
			Rationale: "Force the budget below the ConfigMap count",
		},
	}
	if err := f.Client.Update(context.TODO(), tp); err != nil {
		t.Fatalf("Failed to set setValues on the TailoredProfile: %v", err)
	}

	if err := f.RescanSuite(suiteName, testNamespace); err != nil {
		t.Fatalf("Failed to rescan suite: %v", err)
	}
	// Wait for the scans to restart before waiting for the new result, so a
	// stale DONE/COMPLIANT read cannot be mistaken for the rescan's outcome.
	if err := f.WaitForSuiteScansStatus(testNamespace, suiteName, compv1alpha1.PhaseRunning, compv1alpha1.ResultNotAvailable); err != nil {
		t.Fatalf("Scans did not restart after rescan: %v", err)
	}
	if err := f.WaitForSuiteScansStatus(testNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatalf("Scan with setValues override did not fail as expected: %v", err)
	}
	failCheck := passCheck
	failCheck.Status = compv1alpha1.CheckResultFail
	if err := f.AssertHasCheck(suiteName, scanName, failCheck); err != nil {
		t.Fatalf("Expected FAIL with the setValues override: %v", err)
	}

	// setValues must never mutate the Variable CR.
	stored := &compv1alpha1.Variable{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: varName, Namespace: testNamespace}, stored); err != nil {
		t.Fatal(err)
	}
	if stored.Value != "100000" {
		t.Fatalf("setValues must not mutate the Variable CR: want value 100000, got %q", stored.Value)
	}
}
