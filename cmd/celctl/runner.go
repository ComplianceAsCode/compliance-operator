// runner.go — CEL evaluation through the vendored compliance-sdk scanner.
//
// celctl does not implement a CEL environment of its own: expressions are
// compiled and evaluated by the exact scanner package the operator's
// cel-scanner runs (same stdlib + parseJSON/parseYAML functions, same binding
// and `no such key` -> FAIL semantics), so results here match the operator by
// construction.
package main

import (
	"context"
	"fmt"

	"github.com/ComplianceAsCode/compliance-sdk/pkg/fetchers"
	"github.com/ComplianceAsCode/compliance-sdk/pkg/scanner"
	"k8s.io/client-go/kubernetes"
	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	clientconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
)

// quietLogger silences SDK logging; celctl prints its own output.
type quietLogger struct{}

func (quietLogger) Debug(string, ...interface{}) {}
func (quietLogger) Info(string, ...interface{})  {}
func (quietLogger) Warn(string, ...interface{})  {}
func (quietLogger) Error(string, ...interface{}) {}

// ----- adapters onto the SDK interfaces -----

type adhocInputSpec struct {
	group, version, resource, namespace, name string
}

func (s adhocInputSpec) Validate() error      { return nil }
func (s adhocInputSpec) ApiGroup() string     { return s.group }
func (s adhocInputSpec) Version() string      { return s.version }
func (s adhocInputSpec) ResourceType() string { return s.resource }
func (s adhocInputSpec) Namespace() string    { return s.namespace }
func (s adhocInputSpec) Name() string         { return s.name }

type adhocInput struct {
	name string
	spec adhocInputSpec
}

func (i adhocInput) Name() string            { return i.name }
func (i adhocInput) Type() scanner.InputType { return scanner.InputTypeKubernetes }
func (i adhocInput) Spec() scanner.InputSpec { return i.spec }

type adhocRule struct {
	id     string
	expr   string
	inputs []scanner.Input
}

func (r adhocRule) Identifier() string              { return r.id }
func (r adhocRule) Type() scanner.RuleType          { return scanner.RuleTypeCEL }
func (r adhocRule) Inputs() []scanner.Input         { return r.inputs }
func (r adhocRule) Metadata() *scanner.RuleMetadata { return &scanner.RuleMetadata{Name: r.id} }
func (r adhocRule) Content() interface{}            { return r.expr }
func (r adhocRule) Expression() string              { return r.expr }

// mapFetcher serves pre-bound variables (fixtures / mock data) to the scanner.
type mapFetcher struct {
	vars map[string]interface{}
}

func (f mapFetcher) FetchResources(context.Context, scanner.Rule, []scanner.CelVariable) (map[string]interface{}, []string, error) {
	return f.vars, nil, nil
}

// kubeFetcherAdapter exposes the SDK Kubernetes fetcher (the operator's real
// fetch path) as a scanner.ResourceFetcher.
type kubeFetcherAdapter struct {
	fetcher *fetchers.KubernetesFetcher
}

func (a kubeFetcherAdapter) FetchResources(_ context.Context, rule scanner.Rule, variables []scanner.CelVariable) (map[string]interface{}, []string, error) {
	m, err := a.fetcher.FetchInputs(rule.Inputs(), variables)
	return m, nil, err
}

func newKubeFetcher() (scanner.ResourceFetcher, error) {
	cfg, err := clientconfig.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("no usable kubeconfig (set KUBECONFIG or run in-cluster): %w", err)
	}
	cl, err := runtimeclient.New(cfg, runtimeclient.Options{})
	if err != nil {
		return nil, err
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return kubeFetcherAdapter{fetchers.NewKubernetesFetcher(cl, cs)}, nil
}

// ----- evaluation entry points -----

// evalOutcome is the scanner's verdict for one expression run.
type evalOutcome struct {
	status   scanner.CheckResultStatus
	warnings []string
	errMsg   string
}

func (o evalOutcome) pass() bool { return o.status == scanner.CheckResultPass }

// runRule executes a single rule through the SDK scanner with the given fetcher.
func runRule(rule scanner.Rule, fetcher scanner.ResourceFetcher) (evalOutcome, error) {
	s := scanner.NewScanner(fetcher, quietLogger{})
	results, err := s.Scan(context.Background(), scanner.ScanConfig{Rules: []scanner.Rule{rule}})
	if err != nil {
		return evalOutcome{}, err
	}
	if len(results) != 1 {
		return evalOutcome{}, fmt.Errorf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	return evalOutcome{status: r.Status, warnings: r.Warnings, errMsg: r.ErrorMessage}, nil
}

// evalVars evaluates an expression against pre-bound variables.
func evalVars(expr string, vars map[string]interface{}) (evalOutcome, error) {
	inputs := make([]scanner.Input, 0, len(vars))
	for name := range vars {
		inputs = append(inputs, adhocInput{name: name})
	}
	return runRule(adhocRule{id: "celctl", expr: expr, inputs: inputs}, mapFetcher{vars})
}

// evalExpr keeps the boolean convenience signature used by the ad-hoc
// commands: PASS -> true, FAIL -> false, anything else -> error.
func evalExpr(expr string, vars map[string]interface{}) (bool, error) {
	out, err := evalVars(expr, vars)
	if err != nil {
		return false, err
	}
	switch out.status {
	case scanner.CheckResultPass:
		return true, nil
	case scanner.CheckResultFail:
		return false, nil
	default:
		return false, fmt.Errorf("%s: %s", out.status, out.errMsg)
	}
}
