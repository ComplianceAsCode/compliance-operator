package celvalidation

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/cel-go/checker/decls"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-sdk/pkg/scanner"
)

// celIdentifierRE matches legal CEL identifiers.
var celIdentifierRE = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// celReservedWords are CEL keywords, plus the standard type identifiers
// (int, list, map, ...) that expressions use in value position, e.g.
// type(x) == list. Binding a variable under one of these would shadow the
// type name for every rule in the scan.
var celReservedWords = map[string]bool{
	"true": true, "false": true, "null": true, "in": true, "as": true,
	"break": true, "const": true, "continue": true, "else": true, "for": true,
	"function": true, "if": true, "import": true, "let": true, "loop": true,
	"package": true, "namespace": true, "return": true, "var": true,
	"void": true, "while": true,
	"int": true, "uint": true, "double": true, "bool": true, "string": true,
	"bytes": true, "list": true, "map": true, "type": true, "null_type": true,
	"dyn": true, "timestamp": true, "duration": true,
}

// DeriveCelIdentifier converts a Variable CR name into the CEL identifier it
// is automatically bound under: dashes become underscores
// (ocp4-var-max-pods -> ocp4_var_max_pods). Kubernetes resource names cannot
// contain underscores, so the mapping is unambiguous and reversible. The
// second return is false when the result is not usable as an identifier:
// it starts with a digit, is a CEL reserved word or standard type name, or
// the CR name contains characters CEL identifiers cannot (dots — DNS-1123
// subdomain names such as team.max-pods are not bindable and must be
// referenced through a differently named Variable).
func DeriveCelIdentifier(crName string) (string, bool) {
	derived := strings.ReplaceAll(crName, "-", "_")
	if !celIdentifierRE.MatchString(derived) || celReservedWords[derived] {
		return "", false
	}
	return derived, true
}

// ValidateCELRule compiles and structurally validates a CEL expression
// within a RulePayload. Used by both the Rule and CustomRule controllers.
func ValidateCELRule(name string, payload *v1alpha1.RulePayload) error {
	return ValidateCELRuleWithClusterVariables(name, payload, nil)
}

// ValidateCELRuleWithClusterVariables compiles the expression declaring the
// rule's inputs plus the auto-derived CEL identifier of each given Variable CR
// name (see DeriveCelIdentifier), so expressions may reference in-scope
// variables as bare identifiers: int(ocp4_var_max_pods) for the Variable
// ocp4-var-max-pods. An input name always wins over a derived variable name,
// mirroring the scanner's evaluation-time behavior.
func ValidateCELRuleWithClusterVariables(name string, payload *v1alpha1.RulePayload, clusterVariableNames []string) error {
	inputs := payload.ToScannerInputs()

	declsList := make([]*expr.Decl, 0, len(inputs)+len(clusterVariableNames))
	taken := make(map[string]bool, len(inputs)+len(clusterVariableNames))
	for _, in := range inputs {
		declsList = append(declsList, decls.NewVar(in.Name(), decls.Dyn))
		taken[in.Name()] = true
	}
	for _, crName := range clusterVariableNames {
		derived, ok := DeriveCelIdentifier(crName)
		if !ok || taken[derived] {
			continue
		}
		taken[derived] = true
		declsList = append(declsList, decls.NewVar(derived, decls.String))
	}

	validator := scanner.NewRuleValidator(nil)
	if issues := validator.ValidateCELExpressionWithInputs(payload.Expression, declsList); len(issues) > 0 {
		return fmt.Errorf("CEL expression compilation failed: %w", formatIssues(issues))
	}

	builder := scanner.NewRuleBuilder(name, scanner.RuleTypeCEL)
	for _, input := range inputs {
		builder.WithInput(input)
	}
	builder.SetCelExpression(payload.Expression)

	if payload.Description != "" || payload.Title != "" {
		builder.WithMetadata(&scanner.RuleMetadata{
			Name:        payload.Title,
			Description: payload.Description,
		})
	}

	if _, err := builder.BuildCelRule(); err != nil {
		return fmt.Errorf("CEL rule build validation failed: %w", err)
	}

	return nil
}

// formatIssues renders validation issues the same way the SDK's
// CompileCELExpression does, so error messages stay consistent.
func formatIssues(issues []scanner.ValidationIssue) error {
	msgs := make([]string, 0, len(issues))
	for _, issue := range issues {
		m := fmt.Sprintf("%s: %s", issue.Type, issue.Message)
		if issue.Details != "" {
			m += " - " + issue.Details
		}
		if issue.Location != nil {
			m += fmt.Sprintf(" (at line %d, column %d)", issue.Location.Line, issue.Location.Column)
		}
		msgs = append(msgs, m)
	}
	return errors.New(strings.Join(msgs, "; "))
}
