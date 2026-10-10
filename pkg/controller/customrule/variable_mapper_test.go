package customrule

import (
	"context"
	"testing"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func mapperRule(name, ns, phase, expr string) *v1alpha1.CustomRule {
	return &v1alpha1.CustomRule{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       v1alpha1.CustomRuleSpec{RulePayload: v1alpha1.RulePayload{Expression: expr}},
		Status:     v1alpha1.CustomRuleStatus{Phase: phase},
	}
}

func TestVariableMapperEnqueuesReferencingRulesAnyPhase(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.SchemeBuilder.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(
		mapperRule("errored-ref", "ns-a", v1alpha1.CustomRulePhaseError, `cms.items.size() <= int(ocp4_var_x)`),
		mapperRule("ready-ref", "ns-a", v1alpha1.CustomRulePhaseReady, `int(ocp4_var_x) > 0`),
		mapperRule("unrelated", "ns-a", v1alpha1.CustomRulePhaseError, `int(ocp4_var_other) > 0`),
		mapperRule("prefix-only", "ns-a", v1alpha1.CustomRulePhaseError, `int(ocp4_var_xy) > 0`),
		mapperRule("other-ns-ref", "ns-b", v1alpha1.CustomRulePhaseError, `int(ocp4_var_x) > 0`),
	).Build()

	m := &variableMapper{Client: cl}
	reqs := m.Map(context.TODO(), &v1alpha1.Variable{ObjectMeta: metav1.ObjectMeta{Name: "ocp4-var-x", Namespace: "ns-a"}})

	got := map[string]bool{}
	for _, r := range reqs {
		got[r.Namespace+"/"+r.Name] = true
	}
	want := map[string]bool{"ns-a/errored-ref": true, "ns-a/ready-ref": true}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for k := range want {
		if !got[k] {
			t.Fatalf("expected %s to be enqueued, got %v", k, got)
		}
	}

	if reqs := m.Map(context.TODO(), &v1alpha1.Variable{ObjectMeta: metav1.ObjectMeta{Name: "in", Namespace: "ns-a"}}); len(reqs) != 0 {
		t.Fatalf("a Variable that derives to no usable identifier must enqueue nothing, got %v", reqs)
	}
}
