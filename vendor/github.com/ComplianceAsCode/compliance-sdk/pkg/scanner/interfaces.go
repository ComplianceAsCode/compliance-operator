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
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

// RuleType represents the type of rule/scanner
type RuleType string

const (
	// RuleTypeCEL represents CEL (Common Expression Language) rules
	RuleTypeCEL RuleType = "cel"

	// RuleTypeRego represents Rego (OPA Policy Language) rules - future implementation
	RuleTypeRego RuleType = "rego"

	// RuleTypeJSONPath represents JSONPath expression rules - future implementation
	RuleTypeJSONPath RuleType = "jsonpath"

	// RuleTypeCustom represents custom rule implementations - future implementation
	RuleTypeCustom RuleType = "custom"
)

// Rule defines a generic interface for all rule types
type Rule interface {
	// Identifier returns a unique identifier for this rule
	Identifier() string

	// Type returns the rule type (CEL, Rego, etc.)
	Type() RuleType

	// Inputs returns the list of inputs needed for evaluation
	Inputs() []Input

	// Metadata returns optional rule metadata for compliance reporting
	Metadata() *RuleMetadata

	// Content returns the rule-specific content (expression, policy, etc.)
	Content() interface{}
}

// CelRule defines what's needed for CEL expression evaluation
type CelRule interface {
	Rule

	// Expression returns the CEL expression to evaluate
	Expression() string
}

// ScanEnvironment contains information about the environment where the scan is running
type ScanEnvironment struct {
	// TODO: Add environment information
}

// RuleMetadata contains metadata information for a rule
type RuleMetadata struct {
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Extensions  map[string]interface{} `json:"extensions,omitempty"`
}

// CheckResultMetadata contains metadata information for a check result
type CheckResultMetadata struct {
	Environment ScanEnvironment        `json:"environment,omitempty"`
	Extensions  map[string]interface{} `json:"extensions,omitempty"`
}

// Input defines a generic input that a CEL rule needs
type Input interface {
	// Name returns the name to bind this input to in the CEL context
	Name() string

	// Type returns the type of input (kubernetes, file, system, etc.)
	Type() InputType

	// Spec returns the input specification
	Spec() InputSpec
}

// InputType represents the different types of inputs supported
type InputType string

const (
	// InputTypeKubernetes represents Kubernetes resources
	InputTypeKubernetes InputType = "kubernetes"

	// InputTypeFile represents file system inputs
	InputTypeFile InputType = "file"

	// InputTypeSystem represents system service/process inputs
	InputTypeSystem InputType = "system"

	// InputTypeHTTP represents HTTP API inputs
	InputTypeHTTP InputType = "http"

	// InputTypeDatabase represents database inputs
	InputTypeDatabase InputType = "database"
)

// InputSpec is a generic interface for input specifications
type InputSpec interface {
	// Validate checks if the input specification is valid
	Validate() error
}

// KubernetesInputSpec specifies a Kubernetes resource input
type KubernetesInputSpec interface {
	InputSpec

	// ApiGroup returns the API group (e.g., "apps", "")
	ApiGroup() string

	// Version returns the API version (e.g., "v1", "v1beta1")
	Version() string

	// ResourceType returns the resource type (e.g., "pods", "configmaps")
	ResourceType() string

	// Namespace returns the namespace to search in (empty for cluster-scoped)
	Namespace() string

	// Name returns the specific resource name (empty for all resources)
	Name() string
}

// FileInputSpec specifies a file system input
type FileInputSpec interface {
	InputSpec

	// Path returns the file or directory path
	Path() string

	// Format returns the expected file format (json, yaml, text, etc.)
	Format() string

	// Recursive indicates if directory traversal should be recursive
	Recursive() bool

	// CheckPermissions indicates if file permissions should be included
	CheckPermissions() bool
}

// SystemInputSpec specifies a system service/process input
type SystemInputSpec interface {
	InputSpec

	// ServiceName returns the system service name
	ServiceName() string

	// Command returns the command to execute (alternative to service)
	Command() string

	// Args returns command arguments
	Args() []string
}

// HTTPInputSpec specifies an HTTP API input
type HTTPInputSpec interface {
	InputSpec

	// URL returns the HTTP endpoint URL
	URL() string

	// Method returns the HTTP method (GET, POST, etc.)
	Method() string

	// Headers returns HTTP headers
	Headers() map[string]string

	// Body returns the request body
	Body() []byte
}

// CelVariable defines a variable available in CEL expressions
type CelVariable interface {
	// Name returns the variable name
	Name() string

	// Namespace returns the namespace context
	Namespace() string

	// Value returns the variable value
	Value() string

	// GroupVersionKind returns the Kubernetes GVK for this variable
	GroupVersionKind() schema.GroupVersionKind
}

// InputFetcher retrieves data for different input types
type InputFetcher interface {
	// FetchInputs retrieves data for the specified inputs
	FetchInputs(inputs []Input, variables []CelVariable) (map[string]interface{}, error)

	// SupportsInputType returns whether this fetcher supports the given input type
	SupportsInputType(inputType InputType) bool
}

// ScanLogger handles logging during CEL evaluation
type ScanLogger interface {
	// Debug logs debug information
	Debug(msg string, args ...interface{})

	// Info logs informational messages
	Info(msg string, args ...interface{})

	// Error logs error messages
	Error(msg string, args ...interface{})
}

// ScanResult represents the result of evaluating a CEL rule
type ScanResult struct {
	// RuleID is the identifier of the rule that was evaluated
	RuleID string

	// Status indicates the result of the evaluation
	Status ScanStatus

	// Message provides additional context about the result
	Message string

	// Details contains any additional result data
	Details map[string]interface{}
}

// ScanStatus represents the possible outcomes of a CEL rule evaluation
type ScanStatus string

const (
	// StatusPass indicates the rule evaluation passed
	StatusPass ScanStatus = "PASS"

	// StatusFail indicates the rule evaluation failed
	StatusFail ScanStatus = "FAIL"

	// StatusError indicates an error occurred during evaluation
	StatusError ScanStatus = "ERROR"

	// StatusSkip indicates the rule was skipped
	StatusSkip ScanStatus = "SKIP"
)

// ===== IMPLEMENTATION TYPES =====

// BaseRule provides common functionality for all rule types
type BaseRule struct {
	ID           string        `json:"id"`
	RuleType     RuleType      `json:"type"`
	RuleInputs   []Input       `json:"inputs"`
	RuleMetadata *RuleMetadata `json:"metadata,omitempty"`
}

// Identifier returns the rule ID
func (r *BaseRule) Identifier() string { return r.ID }

// Type returns the rule type
func (r *BaseRule) Type() RuleType { return r.RuleType }

// Inputs returns the rule inputs
func (r *BaseRule) Inputs() []Input { return r.RuleInputs }

// Metadata returns the rule metadata
func (r *BaseRule) Metadata() *RuleMetadata { return r.RuleMetadata }

// CelRuleImpl provides a complete implementation of CelRule
type CelRuleImpl struct {
	BaseRule
	CelExpr string `json:"expression"`
}

// Expression returns the CEL expression
func (r *CelRuleImpl) Expression() string { return r.CelExpr }

// Content returns the CEL expression as the rule content
func (r *CelRuleImpl) Content() interface{} { return r.CelExpr }

// InputImpl provides a concrete implementation of the Input interface
type InputImpl struct {
	InputName string    `json:"name"`
	InputType InputType `json:"type"`
	InputSpec InputSpec `json:"spec"`
}

func (i *InputImpl) Name() string    { return i.InputName }
func (i *InputImpl) Type() InputType { return i.InputType }
func (i *InputImpl) Spec() InputSpec { return i.InputSpec }

// KubernetesInput provides a concrete implementation of KubernetesInputSpec
type KubernetesInput struct {
	Group   string `json:"group"`
	Ver     string `json:"version"`
	ResType string `json:"resourceType"`
	Ns      string `json:"namespace,omitempty"`
	ResName string `json:"name,omitempty"`
}

func (s *KubernetesInput) ApiGroup() string     { return s.Group }
func (s *KubernetesInput) Version() string      { return s.Ver }
func (s *KubernetesInput) ResourceType() string { return s.ResType }
func (s *KubernetesInput) Namespace() string    { return s.Ns }
func (s *KubernetesInput) Name() string         { return s.ResName }
func (s *KubernetesInput) Validate() error      { return nil }

// FileInput provides a concrete implementation of FileInputSpec
type FileInput struct {
	FilePath    string `json:"path"`
	FileFormat  string `json:"format,omitempty"`
	IsRecursive bool   `json:"recursive,omitempty"`
	CheckPerms  bool   `json:"checkPermissions,omitempty"`
}

func (s *FileInput) Path() string           { return s.FilePath }
func (s *FileInput) Format() string         { return s.FileFormat }
func (s *FileInput) Recursive() bool        { return s.IsRecursive }
func (s *FileInput) CheckPermissions() bool { return s.CheckPerms }
func (s *FileInput) Validate() error        { return nil }

// SystemInput provides a concrete implementation of SystemInputSpec
type SystemInput struct {
	Service string   `json:"service,omitempty"`
	Cmd     string   `json:"command,omitempty"`
	CmdArgs []string `json:"args,omitempty"`
}

func (s *SystemInput) ServiceName() string { return s.Service }
func (s *SystemInput) Command() string     { return s.Cmd }
func (s *SystemInput) Args() []string      { return s.CmdArgs }
func (s *SystemInput) Validate() error     { return nil }

// HTTPInput provides a concrete implementation of HTTPInputSpec
type HTTPInput struct {
	Endpoint    string            `json:"url"`
	HTTPMethod  string            `json:"method,omitempty"`
	HTTPHeaders map[string]string `json:"headers,omitempty"`
	HTTPBody    []byte            `json:"body,omitempty"`
}

func (s *HTTPInput) URL() string                { return s.Endpoint }
func (s *HTTPInput) Method() string             { return s.HTTPMethod }
func (s *HTTPInput) Headers() map[string]string { return s.HTTPHeaders }
func (s *HTTPInput) Body() []byte               { return s.HTTPBody }
func (s *HTTPInput) Validate() error            { return nil }

// ===== CONVENIENCE CONSTRUCTORS =====

// NewCelRule creates a new CEL rule with optional metadata
func NewCelRule(id, expression string, inputs []Input) CelRule {
	return &CelRuleImpl{
		BaseRule: BaseRule{
			ID:         id,
			RuleType:   RuleTypeCEL,
			RuleInputs: inputs,
		},
		CelExpr: expression,
	}
}

// NewCelRuleWithMetadata creates a new CEL rule with metadata
func NewCelRuleWithMetadata(id, expression string, inputs []Input, metadata *RuleMetadata) CelRule {
	return &CelRuleImpl{
		BaseRule: BaseRule{
			ID:           id,
			RuleType:     RuleTypeCEL,
			RuleInputs:   inputs,
			RuleMetadata: metadata,
		},
		CelExpr: expression,
	}
}

// NewKubernetesInput creates a Kubernetes resource input
func NewKubernetesInput(name, group, version, resourceType, namespace, resourceName string) Input {
	return &InputImpl{
		InputName: name,
		InputType: InputTypeKubernetes,
		InputSpec: &KubernetesInput{
			Group:   group,
			Ver:     version,
			ResType: resourceType,
			Ns:      namespace,
			ResName: resourceName,
		},
	}
}

// NewFileInput creates a file system input
func NewFileInput(name, path, format string, recursive bool, checkPermissions bool) Input {
	return &InputImpl{
		InputName: name,
		InputType: InputTypeFile,
		InputSpec: &FileInput{
			FilePath:    path,
			FileFormat:  format,
			IsRecursive: recursive,
			CheckPerms:  checkPermissions,
		},
	}
}

// NewSystemInput creates a system service/process input
func NewSystemInput(name, service, command string, args []string) Input {
	return &InputImpl{
		InputName: name,
		InputType: InputTypeSystem,
		InputSpec: &SystemInput{
			Service: service,
			Cmd:     command,
			CmdArgs: args,
		},
	}
}

// NewHTTPInput creates an HTTP API input
func NewHTTPInput(name, url, method string, headers map[string]string, body []byte) Input {
	return &InputImpl{
		InputName: name,
		InputType: InputTypeHTTP,
		InputSpec: &HTTPInput{
			Endpoint:    url,
			HTTPMethod:  method,
			HTTPHeaders: headers,
			HTTPBody:    body,
		},
	}
}

// ===== BUILDER PATTERN =====

// RuleBuilder provides a fluent API for building rules
type RuleBuilder struct {
	id       string
	ruleType RuleType
	inputs   []Input
	metadata *RuleMetadata
	// Rule-specific content
	celExpr string
}

// NewRuleBuilder creates a new rule builder with the specified type
func NewRuleBuilder(id string, ruleType RuleType) *RuleBuilder {
	return &RuleBuilder{
		id:       id,
		ruleType: ruleType,
		inputs:   make([]Input, 0),
	}
}

// WithInput adds an input to the rule
func (b *RuleBuilder) WithInput(input Input) *RuleBuilder {
	b.inputs = append(b.inputs, input)
	return b
}

// WithKubernetesInput adds a Kubernetes input to the rule
func (b *RuleBuilder) WithKubernetesInput(name, group, version, resourceType, namespace, resourceName string) *RuleBuilder {
	input := NewKubernetesInput(name, group, version, resourceType, namespace, resourceName)
	return b.WithInput(input)
}

// WithFileInput adds a file input to the rule
func (b *RuleBuilder) WithFileInput(name, path, format string, recursive, checkPermissions bool) *RuleBuilder {
	input := NewFileInput(name, path, format, recursive, checkPermissions)
	return b.WithInput(input)
}

// WithSystemInput adds a system input to the rule
func (b *RuleBuilder) WithSystemInput(name, service, command string, args []string) *RuleBuilder {
	input := NewSystemInput(name, service, command, args)
	return b.WithInput(input)
}

// WithHTTPInput adds an HTTP input to the rule
func (b *RuleBuilder) WithHTTPInput(name, url, method string, headers map[string]string, body []byte) *RuleBuilder {
	input := NewHTTPInput(name, url, method, headers, body)
	return b.WithInput(input)
}

// SetCelExpression sets the CEL expression for CEL rules
func (b *RuleBuilder) SetCelExpression(expression string) *RuleBuilder {
	if b.ruleType != RuleTypeCEL {
		panic(fmt.Sprintf("SetCelExpression called on non-CEL rule type: %s", b.ruleType))
	}
	b.celExpr = expression
	return b
}

// WithMetadata sets the rule metadata
func (b *RuleBuilder) WithMetadata(metadata *RuleMetadata) *RuleBuilder {
	b.metadata = metadata
	return b
}

// WithName sets the rule name in metadata
func (b *RuleBuilder) WithName(name string) *RuleBuilder {
	if b.metadata == nil {
		b.metadata = &RuleMetadata{}
	}
	b.metadata.Name = name
	return b
}

// WithDescription sets the rule description in metadata
func (b *RuleBuilder) WithDescription(description string) *RuleBuilder {
	if b.metadata == nil {
		b.metadata = &RuleMetadata{}
	}
	b.metadata.Description = description
	return b
}

// WithExtension adds an extension to the rule metadata
func (b *RuleBuilder) WithExtension(key string, value interface{}) *RuleBuilder {
	if b.metadata == nil {
		b.metadata = &RuleMetadata{}
	}
	if b.metadata.Extensions == nil {
		b.metadata.Extensions = make(map[string]interface{})
	}
	b.metadata.Extensions[key] = value
	return b
}

// Build returns the completed rule with validation
func (b *RuleBuilder) Build() (Rule, error) {
	// Validate that we have essential components
	if b.id == "" {
		return nil, fmt.Errorf("rule ID is required")
	}
	if len(b.inputs) == 0 {
		return nil, fmt.Errorf("at least one input is required")
	}

	baseRule := BaseRule{
		ID:           b.id,
		RuleType:     b.ruleType,
		RuleInputs:   b.inputs,
		RuleMetadata: b.metadata,
	}

	// Create the appropriate rule type
	switch b.ruleType {
	case RuleTypeCEL:
		if b.celExpr == "" {
			return nil, fmt.Errorf("CEL expression is required for CEL rules")
		}
		return &CelRuleImpl{
			BaseRule: baseRule,
			CelExpr:  b.celExpr,
		}, nil

	case RuleTypeRego, RuleTypeJSONPath, RuleTypeCustom:
		return nil, fmt.Errorf("rule type %s is not yet implemented", b.ruleType)

	default:
		return nil, fmt.Errorf("unsupported rule type: %s", b.ruleType)
	}
}

// BuildCelRule builds and returns a CelRule (convenience method for CEL rules)
func (b *RuleBuilder) BuildCelRule() (CelRule, error) {
	if b.ruleType != RuleTypeCEL {
		return nil, fmt.Errorf("buildCelRule called on non-CEL rule type: %s", b.ruleType)
	}

	rule, err := b.Build()
	if err != nil {
		return nil, err
	}

	celRule, ok := rule.(CelRule)
	if !ok {
		return nil, fmt.Errorf("failed to cast rule to CelRule")
	}

	return celRule, nil
}

// GetAvailableInputNames returns the names of all defined inputs (useful for expression building)
func (b *RuleBuilder) GetAvailableInputNames() []string {
	names := make([]string, len(b.inputs))
	for i, input := range b.inputs {
		names[i] = input.Name()
	}
	return names
}
