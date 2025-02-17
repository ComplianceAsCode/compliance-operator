package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ScannerType string

const (
	ScannerTypeCEL      ScannerType = "CEL"
	ScannerTypeOpenSCAP ScannerType = "OpenSCAP"
	ScannerTypeUnknown  ScannerType = "Unknown"
)

type InputPayload struct {
	// The kubernetes resource that will be used as input
	// +nullable
	// +optional
	KubeResource `json:",inline,omitempty"`
}

type InputResourceType string

const (
	InputResourceTypeKubeResource InputResourceType = "KubeGroupVersionResource"
	InputResourceTypeUnknown      InputResourceType = "Unknown"
)

// ResourceInput defines a Kubernetes resource that will be fetched for CEL evaluation
type KubeResource struct {
	// Name is the variable name used to reference this resource in the CEL expression
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// Type is the type of the resource

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=KubeGroupVersionResource
	Type InputResourceType `json:"type"`

	// APIGroup is the Kubernetes API group of the resource
	// +kubebuilder:validation:Required
	APIGroup string `json:"apiGroup"`

	// Version is the Kubernetes API version of the resource
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Version string `json:"version"`

	// Resource is the Kubernetes resource type
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Resource string `json:"resource"`

	// Namespace is the Kubernetes namespace of the resource
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

type CELPayload struct {

	// ScannerType specifies what type of check this rule performs
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=CEL;OpenSCAP
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
	RulePayload `json:",inline"`
	CELPayload  `json:",inline"`
}

// CustomRuleStatus is intentionally empty.
type CustomRuleStatus struct{}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:resource:path=customrules,scope=Namespaced
// CustomRule is the Schema for the customrules API
type CustomRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              CustomRuleSpec `json:"spec,omitempty"`
	// Status is intentionally left empty.
	Status CustomRuleStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// CustomRuleList contains a list of CustomRule
type CustomRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CustomRule `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CustomRule{}, &CustomRuleList{})
}
