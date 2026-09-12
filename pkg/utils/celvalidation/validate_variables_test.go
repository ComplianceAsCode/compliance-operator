package celvalidation

import (
	"strings"
	"testing"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
)

func payloadWithExpr(expr string) *v1alpha1.RulePayload {
	return &v1alpha1.RulePayload{
		ID:         "test_rule",
		Title:      "test",
		Expression: expr,
		Inputs: []v1alpha1.InputPayload{
			{
				Name: "cms",
				KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
					APIVersion: "v1",
					Resource:   "configmaps",
				},
			},
		},
	}
}

func TestDeriveCelIdentifier(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"ocp4-var-max-pods", "ocp4_var_max_pods", true},
		{"budget", "budget", true},
		{"0abc-def", "", false}, // digit start
		{"in", "", false},       // CEL reserved word
		{"a-b-c", "a_b_c", true},
	}
	for _, c := range cases {
		got, ok := DeriveCelIdentifier(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("DeriveCelIdentifier(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestBareIdentifierValidatesAgainstClusterVariables(t *testing.T) {
	p := payloadWithExpr(`cms.items.size() <= int(ocp4_var_max_cms)`)
	if err := ValidateCELRuleWithClusterVariables("r", p, []string{"ocp4-var-max-cms"}); err != nil {
		t.Fatalf("expected derived identifier to validate, got: %v", err)
	}
}

func TestUnknownIdentifierRejected(t *testing.T) {
	p := payloadWithExpr(`cms.items.size() <= int(ocp4_var_max_cms)`)
	err := ValidateCELRuleWithClusterVariables("r", p, []string{"some-other-var"})
	if err == nil || !strings.Contains(err.Error(), "UNDECLARED_REFERENCE") {
		t.Fatalf("expected UNDECLARED_REFERENCE for unknown identifier, got: %v", err)
	}
	if err := ValidateCELRule("r", p); err == nil {
		t.Fatal("plain ValidateCELRule must also reject the unknown identifier")
	}
}

func TestInputNameWinsOverDerivedVariable(t *testing.T) {
	// A Variable named "cms" derives to the input's name; the input must stay
	// a dynamic list, so .items access keeps compiling.
	p := payloadWithExpr(`cms.items.size() >= 0`)
	if err := ValidateCELRuleWithClusterVariables("r", p, []string{"cms"}); err != nil {
		t.Fatalf("input must take precedence over derived variable name: %v", err)
	}
}

func TestUnusableVariableNamesSkipped(t *testing.T) {
	// Reserved word and digit-led names must not produce declarations (and
	// must not break validation of an expression that doesn't use them).
	p := payloadWithExpr(`cms.items.size() >= 0`)
	if err := ValidateCELRuleWithClusterVariables("r", p, []string{"in", "0bad-name", "team.max-pods"}); err != nil {
		t.Fatalf("unusable variable names must be skipped, got: %v", err)
	}
}

func TestTypeNameVariablesDoNotShadowTypes(t *testing.T) {
	// A Variable named "list" must not be bound as a string: type(x) == list
	// has to keep type-checking against the CEL type name.
	p := payloadWithExpr(`type(cms.items) == list`)
	if err := ValidateCELRuleWithClusterVariables("r", p, []string{"list", "int", "map"}); err != nil {
		t.Fatalf("type names must be excluded from derived identifiers, got: %v", err)
	}
	if _, ok := DeriveCelIdentifier("list"); ok {
		t.Fatal("DeriveCelIdentifier must reject CEL type names")
	}
}
