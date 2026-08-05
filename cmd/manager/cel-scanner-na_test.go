package manager

import (
	"fmt"
	"testing"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestClassifyMissingResourceTypeError(t *testing.T) {
	noMatch := &apimeta.NoKindMatchError{
		GroupKind: schema.GroupKind{Group: "sriovnetwork.openshift.io", Kind: "Sriovnetworks"},
	}
	wrapped := fmt.Errorf("failed to fetch inputs for type kubernetes: %w",
		fmt.Errorf("failed to list resources sriovnetworks: %w", noMatch))

	reason, na := classifyMissingResourceTypeError(wrapped)
	if !na {
		t.Fatal("wrapped NoKindMatchError should classify as not applicable")
	}
	if reason == "" {
		t.Fatal("expected a reason for the not-applicable classification")
	}

	if _, na := classifyMissingResourceTypeError(fmt.Errorf("connection refused")); na {
		t.Fatal("generic errors must not classify as not applicable")
	}
}

func TestMarkNotApplicable(t *testing.T) {
	a := &ComplianceFetcherAdapter{}
	a.markNotApplicable("rule-a", "type absent")
	if got := a.notApplicableRules["rule-a"]; got != "type absent" {
		t.Fatalf("unexpected reason: %q", got)
	}
}
