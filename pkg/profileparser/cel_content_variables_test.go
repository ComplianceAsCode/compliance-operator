package profileparser

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cmpv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func variablesScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := cmpv1alpha1.SchemeBuilder.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func TestListVariableNamesNilConfig(t *testing.T) {
	if names, err := listVariableNames(nil, "ns"); err != nil || names != nil {
		t.Fatalf("nil config must yield no names and no error, got %v, %v", names, err)
	}
	if names, err := listVariableNames(&ParserConfig{}, "ns"); err != nil || names != nil {
		t.Fatalf("nil client must yield no names and no error, got %v, %v", names, err)
	}
}

func TestListVariableNamesScopedToNamespace(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(variablesScheme(t)).WithRuntimeObjects(
		&cmpv1alpha1.Variable{ObjectMeta: metav1.ObjectMeta{Name: "ocp4-var-a", Namespace: "ns"}},
		&cmpv1alpha1.Variable{ObjectMeta: metav1.ObjectMeta{Name: "ocp4-var-b", Namespace: "ns"}},
		&cmpv1alpha1.Variable{ObjectMeta: metav1.ObjectMeta{Name: "leak-me", Namespace: "other"}},
	).Build()
	names, err := listVariableNames(&ParserConfig{Client: cl}, "ns")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, n := range names {
		got[n] = true
	}
	if len(got) != 2 || !got["ocp4-var-a"] || !got["ocp4-var-b"] {
		t.Fatalf("expected the two namespace Variables only, got %v", names)
	}
}

func TestListVariableNamesListError(t *testing.T) {
	listErr := errors.New("simulated list failure")
	cl := fake.NewClientBuilder().WithScheme(variablesScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		List: func(ctx context.Context, c runtimeclient.WithWatch, list runtimeclient.ObjectList, opts ...runtimeclient.ListOption) error {
			return listErr
		},
	}).Build()
	if _, err := listVariableNames(&ParserConfig{Client: cl}, "ns"); !errors.Is(err, listErr) {
		t.Fatalf("expected the list error to be returned, got %v", err)
	}
}

const derivedIdentifierBundle = `rules:
  - name: var-rule
    id: var_rule
    title: ConfigMap budget from a Variable
    description: References a Variable through its derived CEL identifier
    rationale: Testing
    severity: medium
    checkType: Platform
    expression: 'cms.items.size() <= int(test_var_max)'
    inputs:
      - name: cms
        kubernetesInputSpec:
          apiVersion: v1
          resource: configmaps
profiles:
  - name: var-profile
    id: var_profile
    title: Variable profile
    productType: Platform
    rules:
      - var-rule
`

func parseDerivedIdentifierBundle(t *testing.T, objs ...runtime.Object) error {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.yaml")
	if err := os.WriteFile(path, []byte(derivedIdentifierBundle), 0644); err != nil {
		t.Fatal(err)
	}
	pb := &cmpv1alpha1.ProfileBundle{ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "ns"}}
	cl := fake.NewClientBuilder().WithScheme(variablesScheme(t)).WithRuntimeObjects(append(objs, pb)...).Build()
	return ParseCELBundle(path, pb, &ParserConfig{Client: cl, Scheme: cl.Scheme()})
}

func TestParseCELBundleDerivedIdentifierWithVariable(t *testing.T) {
	variable := &cmpv1alpha1.Variable{
		ObjectMeta:      metav1.ObjectMeta{Name: "test-var-max", Namespace: "ns"},
		VariablePayload: cmpv1alpha1.VariablePayload{ID: "test_var_max", Title: "t", Type: cmpv1alpha1.VarTypeNumber, Value: "3"},
	}
	if err := parseDerivedIdentifierBundle(t, variable); err != nil {
		t.Fatalf("bundle rule referencing an existing Variable must parse, got: %v", err)
	}
}

func TestParseCELBundleDerivedIdentifierWithoutVariable(t *testing.T) {
	err := parseDerivedIdentifierBundle(t)
	if err == nil || !strings.Contains(err.Error(), "UNDECLARED_REFERENCE") {
		t.Fatalf("bundle rule referencing a missing Variable must fail validation, got: %v", err)
	}
}
