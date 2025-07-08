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
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// CelRule defines what's needed for CEL expression evaluation
type CelRule interface {
	// Identifier returns a unique identifier for this rule
	Identifier() string

	// Expression returns the CEL expression to evaluate
	Expression() string

	// Inputs returns the list of inputs needed for evaluation
	Inputs() []Input
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

// Simple implementations for common use cases

// SimpleRule provides a basic implementation of CelRule
type SimpleRule struct {
	ID         string
	CelExpr    string
	RuleInputs []Input
}

func (r *SimpleRule) Identifier() string { return r.ID }
func (r *SimpleRule) Expression() string { return r.CelExpr }
func (r *SimpleRule) Inputs() []Input    { return r.RuleInputs }

// SimpleInput provides a basic implementation of Input
type SimpleInput struct {
	InputName string
	InputType InputType
	InputSpec InputSpec
}

func (i *SimpleInput) Name() string    { return i.InputName }
func (i *SimpleInput) Type() InputType { return i.InputType }
func (i *SimpleInput) Spec() InputSpec { return i.InputSpec }

// SimpleKubernetesInputSpec provides a basic implementation of KubernetesInputSpec
type SimpleKubernetesInputSpec struct {
	Group   string
	Ver     string
	ResType string
	Ns      string
	ResName string
}

func (s *SimpleKubernetesInputSpec) ApiGroup() string     { return s.Group }
func (s *SimpleKubernetesInputSpec) Version() string      { return s.Ver }
func (s *SimpleKubernetesInputSpec) ResourceType() string { return s.ResType }
func (s *SimpleKubernetesInputSpec) Namespace() string    { return s.Ns }
func (s *SimpleKubernetesInputSpec) Name() string         { return s.ResName }
func (s *SimpleKubernetesInputSpec) Validate() error      { return nil }

// SimpleFileInputSpec provides a basic implementation of FileInputSpec
type SimpleFileInputSpec struct {
	FilePath    string
	FileFormat  string
	IsRecursive bool
	CheckPerms  bool
}

func (s *SimpleFileInputSpec) Path() string           { return s.FilePath }
func (s *SimpleFileInputSpec) Format() string         { return s.FileFormat }
func (s *SimpleFileInputSpec) Recursive() bool        { return s.IsRecursive }
func (s *SimpleFileInputSpec) CheckPermissions() bool { return s.CheckPerms }
func (s *SimpleFileInputSpec) Validate() error        { return nil }

// SimpleSystemInputSpec provides a basic implementation of SystemInputSpec
type SimpleSystemInputSpec struct {
	Service string
	Cmd     string
	CmdArgs []string
}

func (s *SimpleSystemInputSpec) ServiceName() string { return s.Service }
func (s *SimpleSystemInputSpec) Command() string     { return s.Cmd }
func (s *SimpleSystemInputSpec) Args() []string      { return s.CmdArgs }
func (s *SimpleSystemInputSpec) Validate() error     { return nil }

// Convenience constructors

// NewRule creates a simple CEL rule
func NewRule(id, expression string, inputs []Input) CelRule {
	return &SimpleRule{
		ID:         id,
		CelExpr:    expression,
		RuleInputs: inputs,
	}
}

// NewKubernetesInput creates a Kubernetes resource input
func NewKubernetesInput(name, group, version, resourceType, namespace, resourceName string) Input {
	return &SimpleInput{
		InputName: name,
		InputType: InputTypeKubernetes,
		InputSpec: &SimpleKubernetesInputSpec{
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
	return &SimpleInput{
		InputName: name,
		InputType: InputTypeFile,
		InputSpec: &SimpleFileInputSpec{
			FilePath:    path,
			FileFormat:  format,
			IsRecursive: recursive,
			CheckPerms:  checkPermissions,
		},
	}
}

// NewSystemInput creates a system service/process input
func NewSystemInput(name, service, command string, args []string) Input {
	return &SimpleInput{
		InputName: name,
		InputType: InputTypeSystem,
		InputSpec: &SimpleSystemInputSpec{
			Service: service,
			Cmd:     command,
			CmdArgs: args,
		},
	}
}

// Example usage:
//
// // Check if any pods exist (Kubernetes)
// input := NewKubernetesInput("pods", "", "v1", "pods", "", "")
// rule := NewRule("pods-exist", "pods.items.size() > 0", []Input{input})
//
// // Check file content (File)
// input := NewFileInput("config", "/etc/app/config.yaml", "yaml", false, false)
// rule := NewRule("config-valid", "config.server.port > 0", []Input{input})
//
// // Check file content with permissions (File)
// input := NewFileInput("config", "/etc/app/config.yaml", "yaml", false, true)
// rule := NewRule("config-permissions", "config.perm == '0644' && config.owner == 'root'", []Input{input})
//
// // Check system service status (System)
// input := NewSystemInput("nginx", "nginx", "", []string{})
// rule := NewRule("nginx-running", "nginx.status == 'active'", []Input{input})
//
// // Mixed inputs
// kubeInput := NewKubernetesInput("pods", "", "v1", "pods", "default", "")
// fileInput := NewFileInput("config", "/etc/config.json", "json", false, false)
// rule := NewRule("mixed-check", "pods.items.size() > 0 && config.enabled", []Input{kubeInput, fileInput})
