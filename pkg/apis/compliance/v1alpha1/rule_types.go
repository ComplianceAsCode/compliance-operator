package v1alpha1

import (
	"github.com/ComplianceAsCode/compliance-sdk/pkg/scanner"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// RuleIDAnnotationKey exposes the DNS-friendly name of a rule as an annotation.
// This provides a way to link a result to a Rule object.
// TODO(jaosorior): Decide where this actually belongs... should it be
// here or in the compliance-operator?
const RuleIDAnnotationKey = "compliance.openshift.io/rule"

// RuleHideTagAnnotationKey is the annotation used to mark a rule to be hidden from the
// ComplianceCheckResult
const RuleHideTagAnnotationKey = "compliance.openshift.io/hide-tag"

// RuleVariableAnnotationKey store list of xccdf variables used to render the rule
const RuleVariableAnnotationKey = "compliance.openshift.io/rule-variable"

// RuleProfileAnnotationKey is the annotation used to store which profiles are using a particular rule
const RuleProfileAnnotationKey = "compliance.openshift.io/profiles"

const (
	CheckTypePlatform = "Platform"
	CheckTypeNode     = "Node"
	CheckTypeNone     = ""
)


type RulePayload struct {
	// The ID of the Rule
	ID string `json:"id"`
	// The title of the Rule
	Title string `json:"title"`
	// The description of the Rule
	Description string `json:"description,omitempty"`
	// The rationale of the Rule
	Rationale string `json:"rationale,omitempty"`
	// A discretionary warning about the of the Rule
	Warning string `json:"warning,omitempty"`
	// The severity level
	Severity string `json:"severity,omitempty"`
	// Instructions for auditing this specific rule
	Instructions string `json:"instructions,omitempty"`
	// What type of check will this rule execute:
	// Platform, Node or none (represented by an empty string)
	// For CustomRules, only Platform is supported.
	CheckType string `json:"checkType,omitempty"`
	// The Available fixes
	// +nullable
	// +optional
	// +listType=atomic
	AvailableFixes []FixDefinition `json:"availableFixes,omitempty"`
	// ScannerType denotes which scanner evaluates this rule.
	// All rules must have an explicit scanner type set by the parser or user.
	// +optional
	// +kubebuilder:validation:Enum=OpenSCAP;CEL
	ScannerType ScannerType `json:"scannerType,omitempty"`
	// Expression is the CEL expression to evaluate (required when scannerType=CEL)
	// +optional
	Expression string `json:"expression,omitempty"`
	// Inputs defines the Kubernetes resources that need to be fetched before evaluating the expression
	// +optional
	Inputs []InputPayload `json:"inputs,omitempty"`
	// FailureReason is displayed when a CEL rule evaluation fails
	// +optional
	FailureReason string `json:"failureReason,omitempty"`
}

// +kubebuilder:object:root=true

// Rule is the Schema for the rules API
// +kubebuilder:resource:path=rules,scope=Namespaced
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type Rule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	RulePayload `json:",inline"`
}

// ToScannerInputs converts RulePayload inputs to SDK scanner.Input slice.
// Shared by both Rule and CustomRule to avoid duplication.
func (rp *RulePayload) ToScannerInputs() []scanner.Input {
	inputs := make([]scanner.Input, 0, len(rp.Inputs))
	for _, input := range rp.Inputs {
		if input.Name != "" {
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

// ToScannerMetadata builds a scanner.RuleMetadata from RulePayload fields.
// Shared by both Rule and CustomRule to avoid duplication.
func (rp *RulePayload) ToScannerMetadata(name string) *scanner.RuleMetadata {
	return &scanner.RuleMetadata{
		Name:        name,
		Description: rp.Description,
		Extensions: map[string]interface{}{
			"id":             rp.ID,
			"description":    rp.Description,
			"title":          rp.Title,
			"warning":        rp.Warning,
			"checkType":      rp.CheckType,
			"availableFixes": rp.AvailableFixes,
			"rationale":      rp.Rationale,
			"severity":       rp.Severity,
			"instructions":   rp.Instructions,
		},
	}
}

// ===== scanner.Rule and scanner.CelRule interfaces for Rule =====

func (r *Rule) Identifier() string {
	return r.Name
}

func (r *Rule) Type() scanner.RuleType {
	if r.RulePayload.ScannerType == ScannerTypeCEL {
		return scanner.RuleTypeCEL
	}
	return scanner.RuleTypeCustom
}

func (r *Rule) Inputs() []scanner.Input {
	return r.RulePayload.ToScannerInputs()
}

func (r *Rule) Metadata() *scanner.RuleMetadata {
	return r.RulePayload.ToScannerMetadata(r.Name)
}

func (r *Rule) Content() interface{} {
	return r.RulePayload.Expression
}

func (r *Rule) Expression() string {
	return r.RulePayload.Expression
}

// ErrorMessage returns the failure reason for this rule (not part of SDK interface).
func (r *Rule) ErrorMessage() string {
	return r.RulePayload.FailureReason
}

// FixDefinition Specifies a fix or remediation
// that applies to a rule
type FixDefinition struct {
	// The platform that the fix applies to
	Platform string `json:"platform,omitempty"`
	// An estimate of the potential disruption or operational
	// degradation that this fix will impose in the target system
	Disruption string `json:"disruption,omitempty"`
	// an object that should bring the rule into compliance
	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:EmbeddedResource
	// +kubebuilder:validation:nullable
	FixObject *unstructured.Unstructured `json:"fixObject,omitempty"`
}

// +kubebuilder:object:root=true

// RuleList contains a list of Rule
type RuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Rule `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Rule{}, &RuleList{})
}
