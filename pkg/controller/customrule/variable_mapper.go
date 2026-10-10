package customrule

import (
	"context"
	"regexp"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils/celvalidation"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// variableMapper enqueues the CustomRules whose expression references a
// changed Variable through its auto-derived CEL identifier, whatever their
// current phase: a rule created before its Variable is rejected and must be
// revalidated once the Variable appears, and a Ready rule must be
// re-evaluated when its Variable disappears.
type variableMapper struct {
	client.Client
}

func (m *variableMapper) Map(ctx context.Context, obj client.Object) []reconcile.Request {
	var requests []reconcile.Request

	ident, ok := celvalidation.DeriveCelIdentifier(obj.GetName())
	if !ok {
		return requests
	}
	referenced := regexp.MustCompile(`\b` + regexp.QuoteMeta(ident) + `\b`)

	ruleList := v1alpha1.CustomRuleList{}
	if err := m.List(ctx, &ruleList, client.InNamespace(obj.GetNamespace())); err != nil {
		log.FromContext(ctx).Error(err, "Failed to list CustomRules for Variable change", "variable", obj.GetName(), "namespace", obj.GetNamespace())
		return requests
	}

	for i := range ruleList.Items {
		rule := &ruleList.Items[i]
		if !referenced.MatchString(rule.Spec.Expression) {
			continue
		}
		requests = append(requests, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: rule.Name, Namespace: rule.Namespace},
		})
	}
	return requests
}
