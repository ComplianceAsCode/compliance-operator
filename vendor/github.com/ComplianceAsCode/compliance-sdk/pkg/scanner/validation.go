/*
Copyright © 2025 Red Hat Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"sigs.k8s.io/yaml"
)

// ValidationErrorType represents the type of validation error
type ValidationErrorType string

const (
	// ValidationErrorTypeSyntax represents a syntax error in the expression
	ValidationErrorTypeSyntax ValidationErrorType = "SYNTAX_ERROR"

	// ValidationErrorTypeUndeclaredReference represents an undeclared variable reference
	ValidationErrorTypeUndeclaredReference ValidationErrorType = "UNDECLARED_REFERENCE"

	// ValidationErrorTypeType represents a type mismatch error
	ValidationErrorTypeType ValidationErrorType = "TYPE_ERROR"

	// ValidationErrorTypeOverload represents a function overload error
	ValidationErrorTypeOverload ValidationErrorType = "OVERLOAD_ERROR"

	// ValidationErrorTypeGeneral represents a general compilation error
	ValidationErrorTypeGeneral ValidationErrorType = "GENERAL_ERROR"
)

// ValidationIssue represents a single validation issue
type ValidationIssue struct {
	// Type is the type of validation error
	Type ValidationErrorType `json:"type"`

	// Message is the human-readable error message
	Message string `json:"message"`

	// Details provides additional context about the error
	Details string `json:"details,omitempty"`

	// Location provides position information if available
	Location *IssueLocation `json:"location,omitempty"`
}

// IssueLocation represents the location of an issue in the expression
type IssueLocation struct {
	// Line number in the expression (1-based)
	Line int `json:"line,omitempty"`

	// Column number in the expression (1-based)
	Column int `json:"column,omitempty"`

	// Offset is the character offset in the expression
	Offset int `json:"offset,omitempty"`
}

// ValidationResult represents the result of validating a rule
type ValidationResult struct {
	// Valid indicates whether the rule is valid
	Valid bool `json:"valid"`

	// Issues contains any validation issues found
	Issues []ValidationIssue `json:"issues,omitempty"`

	// Warnings contains non-fatal warnings
	Warnings []string `json:"warnings,omitempty"`
}

// RuleValidator provides methods for validating rules
type RuleValidator struct {
	logger Logger
}

// NewRuleValidator creates a new rule validator
func NewRuleValidator(logger Logger) *RuleValidator {
	if logger == nil {
		logger = DefaultLogger{}
	}
	return &RuleValidator{
		logger: logger,
	}
}

// ValidateRule performs full validation of a rule
func (v *RuleValidator) ValidateRule(rule Rule) ValidationResult {
	result := ValidationResult{
		Valid:  true,
		Issues: []ValidationIssue{},
	}

	// Only validate CEL rules for now
	if rule.Type() != RuleTypeCEL {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Validation not implemented for rule type: %s", rule.Type()))
		return result
	}

	celRule, ok := rule.(CelRule)
	if !ok {
		result.Valid = false
		result.Issues = append(result.Issues, ValidationIssue{
			Type:    ValidationErrorTypeGeneral,
			Message: "Rule does not implement CelRule interface",
		})
		return result
	}

	// Create declarations for the rule's inputs
	declsList := v.createDeclarationsForRule(rule)

	// Validate the CEL expression with declarations
	issues := v.ValidateCELExpressionWithInputs(celRule.Expression(), declsList)
	if len(issues) > 0 {
		result.Valid = false
		result.Issues = append(result.Issues, issues...)
	}

	return result
}

// ValidateCELExpressionWithInputs validates a CEL expression with optional declarations
func (v *RuleValidator) ValidateCELExpressionWithInputs(expression string, declarations []*expr.Decl) []ValidationIssue {
	issues := []ValidationIssue{}

	// Create CEL environment with declarations
	env, err := v.createValidationEnvironment(declarations)
	if err != nil {
		issues = append(issues, ValidationIssue{
			Type:    ValidationErrorTypeGeneral,
			Message: "Failed to create validation environment",
			Details: err.Error(),
		})
		return issues
	}

	// Compile the expression
	compileIssues := v.compileCELForValidation(env, expression)
	issues = append(issues, compileIssues...)

	return issues
}

// ValidateCELExpression validates just the syntax of a CEL expression
// without requiring input declarations
func (v *RuleValidator) ValidateCELExpression(expression string) []ValidationIssue {
	return v.ValidateCELExpressionWithInputs(expression, nil)
}

// createDeclarationsForRule creates CEL declarations from a rule's inputs
func (v *RuleValidator) createDeclarationsForRule(rule Rule) []*expr.Decl {
	declsList := []*expr.Decl{}

	// Add declarations for each input
	for _, input := range rule.Inputs() {
		// All Kubernetes resources are treated as dynamic types in CEL
		declsList = append(declsList, decls.NewVar(input.Name(), decls.Dyn))
	}

	return declsList
}

// createValidationEnvironment creates a CEL environment for validation
func (v *RuleValidator) createValidationEnvironment(declarations []*expr.Decl) (*cel.Env, error) {
	// Add custom functions that are available in the scanner
	// Note: parseJSON and parseYAML are custom functions that would be available
	// in the actual scanner environment. For validation, we just need to know
	// they exist, not actually execute them.
	mapStrDyn := cel.MapType(cel.StringType, cel.DynType)

	jsonenvOpts := cel.Function("parseJSON",
		cel.Overload("parseJSON_string",
			[]*cel.Type{cel.StringType}, mapStrDyn, cel.UnaryBinding(parseJSONStringValidator)))

	yamlenvOpts := cel.Function("parseYAML",
		cel.Overload("parseYAML_string",
			[]*cel.Type{cel.StringType}, mapStrDyn, cel.UnaryBinding(parseYAMLStringValidator)))

	opts := []cel.EnvOption{
		cel.StdLib(),
		jsonenvOpts,
		yamlenvOpts,
	}

	// Add variable declarations if provided
	if len(declarations) > 0 {
		opts = append(opts, cel.Declarations(declarations...))
	}

	return cel.NewEnv(opts...)
}

// compileCELForValidation compiles a CEL expression and returns detailed validation issues
func (v *RuleValidator) compileCELForValidation(env *cel.Env, expression string) []ValidationIssue {
	issues := []ValidationIssue{}

	_, compileIssues := env.Compile(expression)
	if compileIssues.Err() != nil {
		errMsg := compileIssues.Err().Error()

		// Determine the type of error and create appropriate issue
		issue := v.categorizeCompilationError(expression, errMsg)
		issues = append(issues, issue)

		// Also add any additional issues from the CEL issues object
		for _, celIssue := range compileIssues.Errors() {
			location := &IssueLocation{}
			if celIssue.Location != nil {
				location.Line = int(celIssue.Location.Line())
				location.Column = int(celIssue.Location.Column())
			}

			issues = append(issues, ValidationIssue{
				Type:     v.determineErrorType(celIssue.Message),
				Message:  celIssue.Message,
				Location: location,
			})
		}
	}

	return issues
}

// categorizeCompilationError categorizes a compilation error and creates an issue
func (v *RuleValidator) categorizeCompilationError(expression string, errMsg string) ValidationIssue {
	issue := ValidationIssue{}

	// Check for undeclared reference errors
	if strings.Contains(errMsg, "undeclared reference") {
		// Extract the undeclared variable name
		lines := strings.Split(errMsg, "\n")
		var undeclaredVar string
		for _, line := range lines {
			if strings.Contains(line, "undeclared reference to") {
				start := strings.Index(line, "'")
				end := strings.LastIndex(line, "'")
				if start != -1 && end != -1 && start < end {
					undeclaredVar = line[start+1 : end]
				}
				break
			}
		}

		issue.Type = ValidationErrorTypeUndeclaredReference
		issue.Message = fmt.Sprintf("Undeclared reference to '%s'", undeclaredVar)
		issue.Details = "Available variables and resources should be declared in rule inputs or variables"
		return issue
	}

	// Check for syntax errors
	if strings.Contains(errMsg, "syntax error") || strings.Contains(errMsg, "ERROR: <input>") {
		issue.Type = ValidationErrorTypeSyntax
		issue.Message = "Syntax error in CEL expression"
		issue.Details = errMsg
		return issue
	}

	// Check for type errors
	if strings.Contains(errMsg, "found no matching overload") {
		issue.Type = ValidationErrorTypeOverload
		issue.Message = "No matching function overload found"
		issue.Details = "Check that you're using correct types and functions"
		return issue
	}

	// Check for general type errors
	if strings.Contains(errMsg, "type") {
		issue.Type = ValidationErrorTypeType
		issue.Message = "Type error in expression"
		issue.Details = errMsg
		return issue
	}

	// Generic compilation error
	issue.Type = ValidationErrorTypeGeneral
	issue.Message = "CEL compilation error"
	issue.Details = errMsg
	return issue
}

// determineErrorType determines the error type from a CEL error message
func (v *RuleValidator) determineErrorType(message string) ValidationErrorType {
	switch {
	case strings.Contains(message, "undeclared"):
		return ValidationErrorTypeUndeclaredReference
	case strings.Contains(message, "syntax"):
		return ValidationErrorTypeSyntax
	case strings.Contains(message, "type"):
		return ValidationErrorTypeType
	case strings.Contains(message, "overload"):
		return ValidationErrorTypeOverload
	default:
		return ValidationErrorTypeGeneral
	}
}

// CompileCELExpression compiles a CEL expression and returns detailed error information
// This is the public version of the compileCelExpression method
func CompileCELExpression(expression string, inputs []Input) error {
	validator := NewRuleValidator(nil)

	// Create declarations from inputs
	declsList := []*expr.Decl{}
	for _, input := range inputs {
		declsList = append(declsList, decls.NewVar(input.Name(), decls.Dyn))
	}

	// Validate the expression
	issues := validator.ValidateCELExpressionWithInputs(expression, declsList)
	if len(issues) > 0 {
		// Build detailed error message
		var errMsgs []string
		for _, issue := range issues {
			msg := fmt.Sprintf("%s: %s", issue.Type, issue.Message)
			if issue.Details != "" {
				msg += " - " + issue.Details
			}
			if issue.Location != nil {
				msg += fmt.Sprintf(" (at line %d, column %d)",
					issue.Location.Line, issue.Location.Column)
			}
			errMsgs = append(errMsgs, msg)
		}
		return errors.New(strings.Join(errMsgs, "; "))
	}

	return nil
}

// parseJSONStringValidator is a placeholder implementation for validation purposes
// The actual implementation is in scanner.go
func parseJSONStringValidator(val ref.Val) ref.Val {
	str := val.(types.String)
	decodedVal := map[string]interface{}{}
	err := json.Unmarshal([]byte(str), &decodedVal)
	if err != nil {
		return types.NewErr("failed to decode '%v' in parseJSON: %v", str, err)
	}
	r, err := types.NewRegistry()
	if err != nil {
		return types.NewErr("failed to create a new registry in parseJSON: %v", err)
	}
	return types.NewDynamicMap(r, decodedVal)
}

// parseYAMLStringValidator is a placeholder implementation for validation purposes
// The actual implementation is in scanner.go
func parseYAMLStringValidator(val ref.Val) ref.Val {
	str := val.(types.String)
	decodedVal := map[string]interface{}{}
	err := yaml.Unmarshal([]byte(str), &decodedVal)
	if err != nil {
		return types.NewErr("failed to decode '%v' in parseYAML: %v", str, err)
	}
	r, err := types.NewRegistry()
	if err != nil {
		return types.NewErr("failed to create a new registry in parseYAML: %v", err)
	}
	return types.NewDynamicMap(r, decodedVal)
}
