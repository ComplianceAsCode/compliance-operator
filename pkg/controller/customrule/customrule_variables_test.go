package customrule

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func variableRule(name string) *v1alpha1.CustomRule {
	return &v1alpha1.CustomRule{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns", Generation: 1},
		Spec: v1alpha1.CustomRuleSpec{RulePayload: v1alpha1.RulePayload{
			ID: name, Title: "t", CheckType: "Platform", ScannerType: v1alpha1.ScannerTypeCEL,
			Expression: `cms.items.size() <= int(ocp4_var_max)`,
			Inputs: []v1alpha1.InputPayload{{
				Name:                "cms",
				KubernetesInputSpec: v1alpha1.KubernetesInputSpec{APIVersion: "v1", Resource: "configmaps"},
			}},
		}},
	}
}

func testVariable() *v1alpha1.Variable {
	return &v1alpha1.Variable{
		ObjectMeta:      metav1.ObjectMeta{Name: "ocp4-var-max", Namespace: "ns"},
		VariablePayload: v1alpha1.VariablePayload{ID: "ocp4_var_max", Title: "t", Type: v1alpha1.VarTypeNumber, Value: "3"},
	}
}

func variableScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := v1alpha1.SchemeBuilder.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func reconcileOnce(t *testing.T, cl client.Client, name string) (*v1alpha1.CustomRule, error) {
	t.Helper()
	r := &CustomRuleReconciler{Client: cl, Scheme: cl.Scheme()}
	_, err := r.Reconcile(context.TODO(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: "ns"}})
	rule := &v1alpha1.CustomRule{}
	if getErr := cl.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: "ns"}, rule); getErr != nil {
		t.Fatal(getErr)
	}
	return rule, err
}

func TestReconcileDerivedVariableIdentifierReady(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(variableScheme(t)).WithStatusSubresource(&v1alpha1.CustomRule{}).
		WithRuntimeObjects(variableRule("r"), testVariable()).Build()
	rule, err := reconcileOnce(t, cl, "r")
	if err != nil {
		t.Fatal(err)
	}
	if rule.Status.Phase != v1alpha1.CustomRulePhaseReady {
		t.Fatalf("expected Ready with the Variable present, got %s: %s", rule.Status.Phase, rule.Status.ErrorMessage)
	}
}

func TestReconcileVariableRemovedRevalidatesToError(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(variableScheme(t)).WithStatusSubresource(&v1alpha1.CustomRule{}).
		WithRuntimeObjects(variableRule("r"), testVariable()).Build()
	if rule, err := reconcileOnce(t, cl, "r"); err != nil || rule.Status.Phase != v1alpha1.CustomRulePhaseReady {
		t.Fatalf("precondition: expected Ready, got %s (%v)", rule.Status.Phase, err)
	}
	if err := cl.Delete(context.TODO(), testVariable()); err != nil {
		t.Fatal(err)
	}
	rule, err := reconcileOnce(t, cl, "r")
	if err != nil {
		t.Fatal(err)
	}
	if rule.Status.Phase != v1alpha1.CustomRulePhaseError || !strings.Contains(rule.Status.ErrorMessage, "UNDECLARED_REFERENCE") {
		t.Fatalf("expected Error with UNDECLARED_REFERENCE after the Variable was removed, got %s: %s", rule.Status.Phase, rule.Status.ErrorMessage)
	}
}

func TestReconcileVariableListFailureRetries(t *testing.T) {
	listErr := errors.New("simulated list failure")
	cl := fake.NewClientBuilder().WithScheme(variableScheme(t)).WithStatusSubresource(&v1alpha1.CustomRule{}).
		WithRuntimeObjects(variableRule("r"), testVariable()).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, isVars := list.(*v1alpha1.VariableList); isVars {
					return listErr
				}
				return c.List(ctx, list, opts...)
			},
		}).Build()
	rule, err := reconcileOnce(t, cl, "r")
	if !errors.Is(err, listErr) {
		t.Fatalf("expected the list error to be returned for retry, got: %v", err)
	}
	if rule.Status.Phase != "" || rule.Status.ErrorMessage != "" {
		t.Fatalf("status must be untouched on a transient list failure, got %s: %s", rule.Status.Phase, rule.Status.ErrorMessage)
	}
}
