/*
Copyright © 2024 Red Hat Inc.
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

package celscanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/yaml"
)

// Rule defines the interface for compliance rules
type Rule interface {
	GetName() string
	GetNamespace() string
	GetID() string
	GetDescription() string
	GetRationale() string
	GetSeverity() string
	GetInstructions() string
	GetTitle() string
	GetErrorMessage() string
	GetExpression() string
	GetInputs() []RuleInput
}

// RuleInput defines the interface for rule inputs
type RuleInput interface {
	GetName() string
	GetKubeResource() KubeResource
}

// KubeResource defines the interface for Kubernetes resources
type KubeResource interface {
	GetAPIGroup() string
	GetVersion() string
	GetResource() string
	GetNamespace() string
	GetName() string
}

// Variable defines the interface for variables
type Variable interface {
	GetName() string
	GetNamespace() string
	GetValue() string
	GetGroupVersionKind() schema.GroupVersionKind
}

// CheckResult represents the result of a compliance check
type CheckResult struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Namespace    string            `json:"namespace"`
	Description  string            `json:"description"`
	Rationale    string            `json:"rationale"`
	Severity     string            `json:"severity"`
	Status       CheckResultStatus `json:"status"`
	Warnings     []string          `json:"warnings"`
	Instructions string            `json:"instructions"`
	Labels       map[string]string `json:"labels,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

// CheckResultStatus represents the status of a check result
type CheckResultStatus string

const (
	CheckResultPass          CheckResultStatus = "PASS"
	CheckResultFail          CheckResultStatus = "FAIL"
	CheckResultError         CheckResultStatus = "ERROR"
	CheckResultNotApplicable CheckResultStatus = "NOT-APPLICABLE"
)

// ResourceFetcher defines the interface for fetching Kubernetes resources
type ResourceFetcher interface {
	FetchResources(ctx context.Context, rule Rule, variables []Variable) (map[string]interface{}, []string, error)
}

// Scanner provides CEL-based compliance scanning functionality
type Scanner struct {
	resourceFetcher ResourceFetcher
	logger          Logger
}

// Logger defines the interface for logging
type Logger interface {
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

// DefaultLogger provides a simple console logger
type DefaultLogger struct{}

func (l DefaultLogger) Debug(msg string, args ...interface{}) {
	fmt.Printf("[DEBUG] "+msg+"\n", args...)
}

func (l DefaultLogger) Info(msg string, args ...interface{}) {
	fmt.Printf("[INFO] "+msg+"\n", args...)
}

func (l DefaultLogger) Warn(msg string, args ...interface{}) {
	fmt.Printf("[WARN] "+msg+"\n", args...)
}

func (l DefaultLogger) Error(msg string, args ...interface{}) {
	fmt.Printf("[ERROR] "+msg+"\n", args...)
}

// NewScanner creates a new CEL scanner instance
func NewScanner(resourceFetcher ResourceFetcher, logger Logger) *Scanner {
	if logger == nil {
		logger = DefaultLogger{}
	}
	return &Scanner{
		resourceFetcher: resourceFetcher,
		logger:          logger,
	}
}

// ScanConfig holds configuration for scanning
type ScanConfig struct {
	Rules              []Rule
	Variables          []Variable
	ApiResourcePath    string
	EnableDebugLogging bool
}

// Scan executes compliance checks for the given rules and returns results
func (s *Scanner) Scan(ctx context.Context, config ScanConfig) ([]CheckResult, error) {
	results := []CheckResult{}

	for _, rule := range config.Rules {
		s.logger.Debug("Processing rule: %s", rule.GetName())

		// Fetch resources for this rule
		var resourceMap map[string]interface{}
		var warnings []string
		var err error

		if config.ApiResourcePath != "" {
			s.logger.Info("Using pre-fetched resources from: %s", config.ApiResourcePath)
			resourceMap = s.collectResourcesFromFiles(config.ApiResourcePath, rule)
		} else {
			s.logger.Info("Fetching resources from API server")
			resourceMap, warnings, err = s.resourceFetcher.FetchResources(ctx, rule, config.Variables)
			if err != nil {
				s.logger.Error("Error fetching resources: %v", err)
				// Continue with empty resource map to allow rule evaluation
				resourceMap = make(map[string]interface{})
			}
		}

		// Create CEL declarations with variables
		declsList := s.createCelDeclarations(resourceMap, config.Variables)

		// Create CEL environment
		env, err := s.createCelEnvironment(declsList)
		if err != nil {
			// Create an error result for this rule and continue with next rule
			result := s.createErrorResultWithContext(rule, warnings, fmt.Sprintf("Failed to create CEL environment: %v", err), resourceMap, config.Variables)
			results = append(results, result)
			s.logger.Error("Failed to create CEL environment for rule %s: %v", rule.GetName(), err)
			continue
		}

		// Compile the CEL expression - handle compilation errors gracefully
		ast, err := s.compileCelExpression(env, rule.GetExpression())
		if err != nil {
			// Create an error result for this rule and continue with next rule
			result := s.createErrorResultWithContext(rule, warnings, fmt.Sprintf("CEL compilation error: %v", err), resourceMap, config.Variables)
			results = append(results, result)
			s.logger.Error("Failed to compile CEL expression for rule %s: %v", rule.GetName(), err)
			continue
		}

		// Evaluate the CEL expression
		result := s.evaluateCelExpression(env, ast, resourceMap, rule, warnings, config.Variables)
		results = append(results, result)
	}

	return results, nil
}

// createErrorResultWithContext creates a CheckResult with ERROR status and detailed context
func (s *Scanner) createErrorResultWithContext(rule Rule, warnings []string, errorMsg string, resourceMap map[string]interface{}, variables []Variable) CheckResult {
	result := CheckResult{
		ID:           rule.GetID(),
		Name:         rule.GetName(),
		Namespace:    rule.GetNamespace(),
		Description:  rule.GetDescription(),
		Rationale:    rule.GetRationale(),
		Severity:     rule.GetSeverity(),
		Instructions: rule.GetInstructions(),
		Status:       CheckResultError,
		Warnings:     warnings,
		Labels:       make(map[string]string),
		Annotations:  make(map[string]string),
	}

	// Add detailed error information
	result.Warnings = append(result.Warnings, errorMsg)

	// Add error details to annotations for programmatic access
	if result.Annotations == nil {
		result.Annotations = make(map[string]string)
	}
	result.Annotations["error.type"] = "compilation"
	result.Annotations["error.detail"] = errorMsg
	result.Annotations["cel.expression"] = rule.GetExpression()

	// Add context about available resources and variables
	if resourceMap != nil {
		var availableResources []string
		for resourceName := range resourceMap {
			availableResources = append(availableResources, resourceName)
		}
		if len(availableResources) > 0 {
			result.Annotations["available.resources"] = strings.Join(availableResources, ", ")
		}
	}

	if variables != nil {
		var availableVars []string
		for _, variable := range variables {
			availableVars = append(availableVars, variable.GetName())
		}
		if len(availableVars) > 0 {
			result.Annotations["available.variables"] = strings.Join(availableVars, ", ")
		}
	}

	// Add rule input information for debugging
	var declaredInputs []string
	for _, input := range rule.GetInputs() {
		declaredInputs = append(declaredInputs, input.GetName())
	}
	if len(declaredInputs) > 0 {
		result.Annotations["declared.inputs"] = strings.Join(declaredInputs, ", ")
	}

	return result
}

// collectResourcesFromFiles collects resources from pre-fetched files
func (s *Scanner) collectResourcesFromFiles(resourceDir string, rule Rule) map[string]interface{} {
	resultMap := make(map[string]interface{})

	for _, input := range rule.GetInputs() {
		kubeResource := input.GetKubeResource()

		// Define the GroupVersionResource for the current input
		gvr := schema.GroupVersionResource{
			Group:    kubeResource.GetAPIGroup(),
			Version:  kubeResource.GetVersion(),
			Resource: kubeResource.GetResource(),
		}

		// Derive the resource path
		objPath := DeriveResourcePath(gvr, kubeResource.GetNamespace()) + ".json"
		filePath := filepath.Join(resourceDir, objPath)

		// Read the file content
		fileContent, err := os.ReadFile(filePath)
		if err != nil {
			s.logger.Error("Failed to read file %s: %v", filePath, err)
			continue
		}

		// Parse based on resource type
		if strings.Contains(kubeResource.GetResource(), "/") {
			// Subresource
			result := &unstructured.Unstructured{}
			if err := json.Unmarshal(fileContent, result); err != nil {
				s.logger.Error("Failed to parse JSON from file %s: %v", filePath, err)
				continue
			}
			resultMap[kubeResource.GetName()] = result
		} else {
			// Regular resource list
			results := &unstructured.UnstructuredList{}
			if err := json.Unmarshal(fileContent, results); err != nil {
				s.logger.Error("Failed to parse JSON from file %s: %v", filePath, err)
				continue
			}
			resultMap[kubeResource.GetName()] = results
		}
	}

	return resultMap
}

// createCelDeclarations creates CEL declarations for the given resource map and variables
func (s *Scanner) createCelDeclarations(resourceMap map[string]interface{}, variables []Variable) []*expr.Decl {
	declsList := []*expr.Decl{}

	// Add resource declarations
	for k := range resourceMap {
		declsList = append(declsList, decls.NewVar(k, decls.Dyn))
	}

	// Add variable declarations
	for _, variable := range variables {
		declsList = append(declsList, decls.NewVar(variable.GetName(), decls.String))
	}

	return declsList
}

// createCelEnvironment creates a CEL environment with custom functions
func (s *Scanner) createCelEnvironment(declsList []*expr.Decl) (*cel.Env, error) {
	mapStrDyn := cel.MapType(cel.StringType, cel.DynType)

	jsonenvOpts := cel.Function("parseJSON",
		cel.MemberOverload("parseJSON_string",
			[]*cel.Type{cel.StringType}, mapStrDyn, cel.UnaryBinding(parseJSONString)))

	yamlenvOpts := cel.Function("parseYAML",
		cel.MemberOverload("parseYAML_string",
			[]*cel.Type{cel.StringType}, mapStrDyn, cel.UnaryBinding(parseYAMLString)))

	env, err := cel.NewEnv(
		cel.Declarations(declsList...),
		jsonenvOpts,
		yamlenvOpts,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %v", err)
	}

	return env, nil
}

// compileCelExpression compiles a CEL expression with detailed error reporting
func (s *Scanner) compileCelExpression(env *cel.Env, expression string) (*cel.Ast, error) {
	ast, issues := env.Compile(expression)
	if issues.Err() != nil {
		// Enhanced error reporting for different types of compilation errors
		errMsg := issues.Err().Error()

		// Check for undeclared reference errors and provide helpful context
		if strings.Contains(errMsg, "undeclared reference") {
			// Extract the undeclared variable name
			lines := strings.Split(errMsg, "\n")
			var undeclaredVar string
			for _, line := range lines {
				if strings.Contains(line, "undeclared reference to") {
					// Extract variable name from error like: undeclared reference to 'variableName'
					start := strings.Index(line, "'")
					end := strings.LastIndex(line, "'")
					if start != -1 && end != -1 && start < end {
						undeclaredVar = line[start+1 : end]
					}
					break
				}
			}

			detailedErr := fmt.Sprintf("CEL compilation failed: undeclared reference to '%s'. "+
				"Available variables and resources should be declared in rule inputs or variables. "+
				"Original error: %v", undeclaredVar, errMsg)
			return nil, fmt.Errorf(detailedErr)
		}

		// Check for syntax errors
		if strings.Contains(errMsg, "syntax error") || strings.Contains(errMsg, "ERROR: <input>") {
			detailedErr := fmt.Sprintf("CEL syntax error in expression '%s': %v", expression, errMsg)
			return nil, fmt.Errorf(detailedErr)
		}

		// Check for type errors
		if strings.Contains(errMsg, "found no matching overload") {
			detailedErr := fmt.Sprintf("CEL type error - no matching function overload found. "+
				"Check that you're using correct types and functions. Expression: '%s'. Error: %v",
				expression, errMsg)
			return nil, fmt.Errorf(detailedErr)
		}

		// Generic compilation error with expression context
		detailedErr := fmt.Sprintf("CEL compilation error in expression '%s': %v", expression, errMsg)
		return nil, fmt.Errorf(detailedErr)
	}
	return ast, nil
}

// evaluateCelExpression evaluates a CEL expression and returns the result
func (s *Scanner) evaluateCelExpression(env *cel.Env, ast *cel.Ast, resourceMap map[string]interface{}, rule Rule, warnings []string, variables []Variable) CheckResult {
	result := CheckResult{
		ID:           rule.GetID(),
		Name:         rule.GetName(),
		Namespace:    rule.GetNamespace(),
		Description:  rule.GetDescription(),
		Rationale:    rule.GetRationale(),
		Severity:     rule.GetSeverity(),
		Instructions: rule.GetInstructions(),
		Warnings:     warnings,
		Labels:       make(map[string]string),
		Annotations:  make(map[string]string),
	}

	// Prepare evaluation variables
	evalVars := map[string]interface{}{}
	for k, v := range resourceMap {
		s.logger.Debug("Evaluating variable %s: %v", k, v)
		evalVars[k] = toCelValue(v)
	}

	// Add variables to evaluation context
	for _, variable := range variables {
		evalVars[variable.GetName()] = variable.GetValue()
	}

	// Create and run the CEL program
	prg, err := env.Program(ast)
	if err != nil {
		result.Status = CheckResultError
		result.Warnings = append(result.Warnings, fmt.Sprintf("Failed to create CEL program: %v", err))
		return result
	}

	out, _, err := prg.Eval(evalVars)
	if err != nil {
		if strings.HasPrefix(err.Error(), "no such key") {
			s.logger.Warn("Warning: %s in rule %s", err, rule.GetName())
			result.Warnings = append(result.Warnings, fmt.Sprintf("Warning: %s", err))
			result.Status = CheckResultFail
			return result
		}

		result.Status = CheckResultError
		result.Warnings = append(result.Warnings, fmt.Sprintf("Failed to evaluate CEL expression: %v", err))
		return result
	}

	// Determine result status based on evaluation outcome
	if out.Value() == false {
		result.Status = CheckResultFail
		if rule.GetErrorMessage() != "" {
			s.logger.Info("Rule failed: %s", rule.GetErrorMessage())
		}
	} else {
		result.Status = CheckResultPass
		s.logger.Info("%s: %v", rule.GetTitle(), out)
	}

	return result
}

// DeriveResourcePath creates a resource path from GroupVersionResource and namespace
func DeriveResourcePath(gvr schema.GroupVersionResource, namespace string) string {
	if namespace != "" {
		return fmt.Sprintf("namespaces/%s/%s", namespace, gvr.Resource)
	}
	return gvr.Resource
}

// SaveResults saves scan results to a JSON file
func SaveResults(filePath string, results []CheckResult) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create result file %s: %v", filePath, err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		return fmt.Errorf("failed to encode results to JSON: %v", err)
	}

	return nil
}

// parseJSONString parses a JSON string for CEL evaluation
func parseJSONString(val ref.Val) ref.Val {
	str := val.(types.String)
	decodedVal := map[string]interface{}{}
	err := json.Unmarshal([]byte(str), &decodedVal)
	if err != nil {
		return types.NewErr("failed to decode '%v' in parseJSON: %w", str, err)
	}
	r, err := types.NewRegistry()
	if err != nil {
		return types.NewErr("failed to create a new registry in parseJSON: %w", err)
	}
	return types.NewDynamicMap(r, decodedVal)
}

// parseYAMLString parses a YAML string for CEL evaluation
func parseYAMLString(val ref.Val) ref.Val {
	str := val.(types.String)
	decodedVal := map[string]interface{}{}
	err := yaml.Unmarshal([]byte(str), &decodedVal)
	if err != nil {
		return types.NewErr("failed to decode '%v' in parseYAML: %w", str, err)
	}
	r, err := types.NewRegistry()
	if err != nil {
		return types.NewErr("failed to create a new registry in parseYAML: %w", err)
	}
	return types.NewDynamicMap(r, decodedVal)
}

// toCelValue converts Kubernetes unstructured objects to CEL values
func toCelValue(u interface{}) interface{} {
	if unstruct, ok := u.(*unstructured.Unstructured); ok {
		return unstruct.Object
	}
	if unstructList, ok := u.(*unstructured.UnstructuredList); ok {
		list := []interface{}{}
		for _, item := range unstructList.Items {
			list = append(list, item.Object)
		}
		return map[string]interface{}{
			"items": list,
		}
	}
	return u
}
