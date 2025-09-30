package v1alpha1

import (
	"fmt"

	"github.com/ComplianceAsCode/compliance-sdk/pkg/scanner"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ScannerType string

const (
	ScannerTypeCEL      ScannerType = "CEL"
	ScannerTypeOpenSCAP ScannerType = "OpenSCAP"
	ScannerTypeUnknown  ScannerType = "Unknown"
)

type InputPayload struct {
	// Name is the variable name used to reference this resource in the CEL expression
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// KubernetesInputSpec is the specification of the Kubernetes resource to fetch
	// +kubebuilder:validation:Required
	KubernetesInputSpec KubernetesInputSpec `json:"kubernetesInputSpec"`
}

// KubernetesInputSpec defines the specification for a Kubernetes resource input
// This is a concrete implementation compatible with the SDK's KubernetesInputSpec interface
type KubernetesInputSpec struct {
	// Group is the API group (e.g., "apps", "" for core resources)
	// +optional
	Group string `json:"group,omitempty"`

	// APIVersion is the API version (e.g., "v1", "v1beta1")
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	APIVersion string `json:"apiVersion"`

	// Resource is the resource type (e.g., "pods", "configmaps")
	// Use the plural form of the resource
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Resource string `json:"resource"`

	// ResourceNamespace is the namespace to search in
	// Leave empty for cluster-scoped resources or to search all namespaces
	// +optional
	ResourceNamespace string `json:"resourceNamespace,omitempty"`

	// ResourceName is the specific resource name
	// Leave empty to fetch all resources of this type
	// +optional
	ResourceName string `json:"resourceName,omitempty"`
}

type CustomRulePayload struct {

	// ScannerType denotes the scanning implementation to use when evaluating rules
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=CEL
	ScannerType ScannerType `json:"scannerType"`

	// Expression is the CEL expression to evaluate
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Expression string `json:"expression"`

	// Inputs defines the Kubernetes resources that need to be fetched before evaluating the expression
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Inputs []InputPayload `json:"inputs"`

	// ErrorMessage is displayed when the rule evaluation fails
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	ErrorMessage string `json:"errorMessage"`
}

type CustomRuleSpec struct {
	RulePayload       `json:",inline"`
	CustomRulePayload `json:",inline"`
}

// CustomRuleStatus defines the observed state of CustomRule
type CustomRuleStatus struct {
	// Phase describes the current phase of the CustomRule (Ready or Error)
	// +kubebuilder:validation:Enum=Ready;Error
	// +optional
	Phase string `json:"phase,omitempty"`

	// ErrorMessage contains any validation error message
	// +optional
	ErrorMessage string `json:"errorMessage,omitempty"`

	// LastValidationTime is the timestamp of the last validation
	// +optional
	LastValidationTime *metav1.Time `json:"lastValidationTime,omitempty"`

	// ObservedGeneration represents the .metadata.generation that the status was set based upon
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// CustomRule phases
const (
	// CustomRulePhaseReady means the rule has been validated and is ready for use
	CustomRulePhaseReady = "Ready"
	// CustomRulePhaseError means the rule validation failed
	CustomRulePhaseError = "Error"
)

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:resource:path=customrules,scope=Namespaced
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Severity",type=string,JSONPath=`.spec.severity`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// CustomRule is the Schema for the customrules API
type CustomRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              CustomRuleSpec `json:"spec,omitempty"`
	// Status contains the validation status and other runtime information
	Status CustomRuleStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// CustomRuleList contains a list of CustomRule
type CustomRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CustomRule `json:"items"`
}

// Implement scanner.KubernetesInputSpec interface methods
// These methods allow KubernetesInputSpec to be used where the SDK interface is expected

// ApiGroup implements scanner.KubernetesInputSpec
func (k *KubernetesInputSpec) ApiGroup() string {
	return k.Group
}

// Version implements scanner.KubernetesInputSpec
func (k *KubernetesInputSpec) Version() string {
	return k.APIVersion
}

// ResourceType implements scanner.KubernetesInputSpec
func (k *KubernetesInputSpec) ResourceType() string {
	return k.Resource
}

// Namespace implements scanner.KubernetesInputSpec
func (k *KubernetesInputSpec) Namespace() string {
	return k.ResourceNamespace
}

// Name implements scanner.KubernetesInputSpec
func (k *KubernetesInputSpec) Name() string {
	return k.ResourceName
}

// Validate implements scanner.InputSpec
func (k *KubernetesInputSpec) Validate() error {
	// Validate required fields
	if k.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}

	if k.Resource == "" {
		return fmt.Errorf("resource is required")
	}

	return nil
}

// ===== Implement scanner.Rule and scanner.CelRule interfaces =====
// These methods allow CustomRule to be used directly with the SDK scanner

// Identifier implements scanner.Rule
func (cr *CustomRule) Identifier() string {
	// Use the rule's Name as the identifier
	return cr.Name
}

// Type implements scanner.Rule
func (cr *CustomRule) Type() scanner.RuleType {
	// CustomRules are always CEL type
	return scanner.RuleTypeCEL
}

// Inputs implements scanner.Rule
func (cr *CustomRule) Inputs() []scanner.Input {
	inputs := make([]scanner.Input, 0, len(cr.Spec.CustomRulePayload.Inputs))
	for _, input := range cr.Spec.CustomRulePayload.Inputs {
		if input.Name != "" {
			// Create SDK-compatible input using our concrete struct
			sdkInput := &scanner.InputImpl{
				InputName: input.Name,
				InputType: scanner.InputTypeKubernetes,
				InputSpec: &input.KubernetesInputSpec,
			}
			inputs = append(inputs, sdkInput)
		}
	}
	return inputs
}

// Metadata implements scanner.Rule
func (cr *CustomRule) Metadata() *scanner.RuleMetadata {
	return &scanner.RuleMetadata{
		Name:        cr.Name,
		Description: cr.Spec.Description,
		Extensions: map[string]interface{}{
			"id":             cr.Spec.ID,
			"description":    cr.Spec.Description,
			"title":          cr.Spec.Title,
			"warning":        cr.Spec.Warning,
			"checkType":      cr.Spec.CheckType,
			"availableFixes": cr.Spec.AvailableFixes,
			"rationale":      cr.Spec.Rationale,
			"severity":       cr.Spec.Severity,
			"instructions":   cr.Spec.Instructions,
		},
	}
}

// Content implements scanner.Rule
func (cr *CustomRule) Content() interface{} {
	return cr.Spec.CustomRulePayload.Expression
}

// Expression implements scanner.CelRule
func (cr *CustomRule) Expression() string {
	return cr.Spec.CustomRulePayload.Expression
}

// ErrorMessage returns the error message to display when the rule fails
func (cr *CustomRule) ErrorMessage() string {
	return cr.Spec.CustomRulePayload.ErrorMessage
}

func init() {
	SchemeBuilder.Register(&CustomRule{}, &CustomRuleList{})
}
