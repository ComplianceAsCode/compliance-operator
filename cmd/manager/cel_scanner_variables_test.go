package manager

import (
	"testing"

	cmpv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-sdk/pkg/scanner"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func varScanner(t *testing.T, objs ...runtime.Object) *CelScanner {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := cmpv1alpha1.SchemeBuilder.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objs...).Build()
	return &CelScanner{client: cl, celConfig: celConfig{NameSpace: "test-ns"}}
}

func variableCR(name, value string) *cmpv1alpha1.Variable {
	return &cmpv1alpha1.Variable{
		ObjectMeta:      metav1.ObjectMeta{Name: name, Namespace: "test-ns"},
		VariablePayload: cmpv1alpha1.VariablePayload{Value: value},
	}
}

func ruleWithInputs(id string, inputNames ...string) celRuleWrapper {
	inputs := make([]cmpv1alpha1.InputPayload, 0, len(inputNames))
	for _, n := range inputNames {
		inputs = append(inputs, cmpv1alpha1.InputPayload{
			Name:                n,
			KubernetesInputSpec: cmpv1alpha1.KubernetesInputSpec{APIVersion: "v1", Resource: "configmaps"},
		})
	}
	cr := &cmpv1alpha1.CustomRule{
		ObjectMeta: metav1.ObjectMeta{Name: id, Namespace: "test-ns"},
		Spec: cmpv1alpha1.CustomRuleSpec{RulePayload: cmpv1alpha1.RulePayload{
			ID: id, Expression: "true", Inputs: inputs,
		}},
	}
	return celRuleWrapper{scannerRule: cr, payload: &cr.Spec.RulePayload}
}

func scanVarMap(t *testing.T, c *CelScanner, setVars []*cmpv1alpha1.Variable) map[string]string {
	t.Helper()
	got, err := c.buildScanVariables(setVars)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, v := range got {
		if _, dup := m[v.Name()]; dup {
			t.Fatalf("duplicate binding for %q", v.Name())
		}
		m[v.Name()] = v.Value()
	}
	return m
}

func TestScanVariablesDerivedFromUniverse(t *testing.T) {
	c := varScanner(t, variableCR("ocp4-var-max", "9999"), variableCR("budget", "7"))
	m := scanVarMap(t, c, nil)
	if m["ocp4_var_max"] != "9999" || m["budget"] != "7" || len(m) != 2 {
		t.Fatalf("unexpected bindings: %v", m)
	}
}

func TestScanVariablesSetValuesOverride(t *testing.T) {
	c := varScanner(t, variableCR("ocp4-var-max", "9999"))
	override := variableCR("ocp4-var-max", "1")
	m := scanVarMap(t, c, []*cmpv1alpha1.Variable{override})
	if m["ocp4_var_max"] != "1" {
		t.Fatalf("setValues must override the stored value, got: %v", m)
	}
}

func TestScanVariablesSetValuesOnlyVariable(t *testing.T) {
	// A setValues entry whose Variable is gone from the List (deleted between
	// the TailoredProfile resolution and the List) is still bound with the
	// tailored value rather than dropped.
	c := varScanner(t)
	m := scanVarMap(t, c, []*cmpv1alpha1.Variable{variableCR("ocp4-var-new", "5")})
	if m["ocp4_var_new"] != "5" {
		t.Fatalf("setValues-only variable must be bound, got: %v", m)
	}
}

func TestVariablesForRuleDropsInputCollisions(t *testing.T) {
	// Input names take precedence per rule: the colliding variable is dropped
	// only for the rule that declares that input, mirroring admission.
	c := varScanner(t, variableCR("cms", "boom"), variableCR("ocp4-var-ok", "1"))
	all, err := c.buildScanVariables(nil)
	if err != nil {
		t.Fatal(err)
	}
	names := func(vs []scanner.CelVariable) map[string]bool {
		m := map[string]bool{}
		for _, v := range vs {
			m[v.Name()] = true
		}
		return m
	}
	withInput := names(variablesForRule(all, ruleWithInputs("r1", "cms")))
	if withInput["cms"] || !withInput["ocp4_var_ok"] {
		t.Fatalf("rule with input cms must not see variable cms but keep others: %v", withInput)
	}
	without := names(variablesForRule(all, ruleWithInputs("r2", "pods")))
	if !without["cms"] || !without["ocp4_var_ok"] {
		t.Fatalf("rule without a colliding input must see every variable: %v", without)
	}
}

func TestScanVariablesScopedToNamespace(t *testing.T) {
	c := varScanner(t, variableCR("ocp4-var-ok", "1"), &cmpv1alpha1.Variable{
		ObjectMeta:      metav1.ObjectMeta{Name: "leak-me", Namespace: "other-ns"},
		VariablePayload: cmpv1alpha1.VariablePayload{Value: "x"},
	})
	m := scanVarMap(t, c, nil)
	if _, leaked := m["leak_me"]; leaked || len(m) != 1 {
		t.Fatalf("variables from other namespaces must not be bound: %v", m)
	}
}

func TestScanVariablesUnusableNamesSkipped(t *testing.T) {
	c := varScanner(t, variableCR("in", "x"), variableCR("list", "y"), variableCR("ocp4-var-ok", "1"))
	m := scanVarMap(t, c, nil)
	if len(m) != 1 || m["ocp4_var_ok"] != "1" {
		t.Fatalf("reserved-word and type-name variables must be skipped: %v", m)
	}
}
