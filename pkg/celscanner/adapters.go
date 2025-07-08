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
	"strings"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// ComplianceOperatorRuleAdapter adapts v1alpha1.CustomRule to the Rule interface
type ComplianceOperatorRuleAdapter struct {
	Rule *v1alpha1.CustomRule
}

func (r *ComplianceOperatorRuleAdapter) GetName() string {
	return r.Rule.Name
}

func (r *ComplianceOperatorRuleAdapter) GetNamespace() string {
	return r.Rule.Namespace
}

func (r *ComplianceOperatorRuleAdapter) GetID() string {
	return r.Rule.Spec.ID
}

func (r *ComplianceOperatorRuleAdapter) GetDescription() string {
	return r.Rule.Spec.Description
}

func (r *ComplianceOperatorRuleAdapter) GetRationale() string {
	return r.Rule.Spec.Rationale
}

func (r *ComplianceOperatorRuleAdapter) GetSeverity() string {
	return string(r.Rule.Spec.Severity)
}

func (r *ComplianceOperatorRuleAdapter) GetInstructions() string {
	return r.Rule.Spec.Instructions
}

func (r *ComplianceOperatorRuleAdapter) GetTitle() string {
	return r.Rule.Spec.Title
}

func (r *ComplianceOperatorRuleAdapter) GetErrorMessage() string {
	return r.Rule.Spec.ErrorMessage
}

func (r *ComplianceOperatorRuleAdapter) GetExpression() string {
	return r.Rule.Spec.Expression
}

func (r *ComplianceOperatorRuleAdapter) GetInputs() []RuleInput {
	inputs := make([]RuleInput, 0, len(r.Rule.Spec.Inputs))
	for _, input := range r.Rule.Spec.Inputs {
		inputs = append(inputs, &ComplianceOperatorRuleInputAdapter{Input: &input})
	}
	return inputs
}

// ComplianceOperatorRuleInputAdapter adapts v1alpha1.InputPayload to the RuleInput interface
type ComplianceOperatorRuleInputAdapter struct {
	Input *v1alpha1.InputPayload
}

func (i *ComplianceOperatorRuleInputAdapter) GetName() string {
	return i.Input.KubeResource.Name
}

func (i *ComplianceOperatorRuleInputAdapter) GetKubeResource() KubeResource {
	return &ComplianceOperatorKubeResourceAdapter{KubeResource: &i.Input.KubeResource}
}

// ComplianceOperatorKubeResourceAdapter adapts v1alpha1.KubeResource to the KubeResource interface
type ComplianceOperatorKubeResourceAdapter struct {
	KubeResource *v1alpha1.KubeResource
}

func (k *ComplianceOperatorKubeResourceAdapter) GetAPIGroup() string {
	return k.KubeResource.APIGroup
}

func (k *ComplianceOperatorKubeResourceAdapter) GetVersion() string {
	return k.KubeResource.Version
}

func (k *ComplianceOperatorKubeResourceAdapter) GetResource() string {
	return k.KubeResource.Resource
}

func (k *ComplianceOperatorKubeResourceAdapter) GetNamespace() string {
	return k.KubeResource.Namespace
}

func (k *ComplianceOperatorKubeResourceAdapter) GetName() string {
	return k.KubeResource.Name
}

// ComplianceOperatorVariableAdapter adapts v1alpha1.Variable to the Variable interface
type ComplianceOperatorVariableAdapter struct {
	Variable *v1alpha1.Variable
}

func (v *ComplianceOperatorVariableAdapter) GetName() string {
	return v.Variable.Name
}

func (v *ComplianceOperatorVariableAdapter) GetNamespace() string {
	return v.Variable.Namespace
}

func (v *ComplianceOperatorVariableAdapter) GetValue() string {
	return v.Variable.Value
}

func (v *ComplianceOperatorVariableAdapter) GetGroupVersionKind() schema.GroupVersionKind {
	return v.Variable.GroupVersionKind()
}

// ComplianceOperatorResourceFetcher implements ResourceFetcher using the original compliance-operator resource fetching logic
type ComplianceOperatorResourceFetcher struct {
	client    runtimeclient.Client
	clientset *kubernetes.Clientset
}

func NewComplianceOperatorResourceFetcher(client runtimeclient.Client, clientset *kubernetes.Clientset) *ComplianceOperatorResourceFetcher {
	return &ComplianceOperatorResourceFetcher{
		client:    client,
		clientset: clientset,
	}
}

func (f *ComplianceOperatorResourceFetcher) FetchResources(ctx context.Context, rule Rule, variables []Variable) (map[string]interface{}, []string, error) {
	// Convert rule to the original type for compatibility
	originalRule := &v1alpha1.CustomRule{
		Spec: v1alpha1.CustomRuleSpec{
			CELPayload: v1alpha1.CELPayload{
				Inputs: make([]v1alpha1.InputPayload, 0, len(rule.GetInputs())),
			},
		},
	}

	for _, input := range rule.GetInputs() {
		kubeResource := input.GetKubeResource()
		originalRule.Spec.Inputs = append(originalRule.Spec.Inputs, v1alpha1.InputPayload{
			KubeResource: v1alpha1.KubeResource{
				Name:      kubeResource.GetName(),
				APIGroup:  kubeResource.GetAPIGroup(),
				Version:   kubeResource.GetVersion(),
				Resource:  kubeResource.GetResource(),
				Namespace: kubeResource.GetNamespace(),
			},
		})
	}

	// Convert variables to the original type
	originalVariables := make([]*v1alpha1.Variable, 0, len(variables))
	for _, variable := range variables {
		originalVar := &v1alpha1.Variable{
			ObjectMeta: metav1.ObjectMeta{
				Name:      variable.GetName(),
				Namespace: variable.GetNamespace(),
			},
			VariablePayload: v1alpha1.VariablePayload{
				Value: variable.GetValue(),
			},
		}
		originalVariables = append(originalVariables, originalVar)
	}

	// Use the original resource fetching logic
	figuredResourcePaths, foundMap, variableResultMap, err := f.figureResources(originalRule, originalVariables)
	if err != nil {
		return nil, nil, fmt.Errorf("error figuring resources: %v", err)
	}

	// Create a simple resource fetcher clients struct
	resourceFetchers := resourceFetcherClients{
		clientset: f.clientset,
		client:    f.client,
	}

	// Use the original fetch function
	found, warnings, err := fetch(ctx, getStreamerFn, resourceFetchers, figuredResourcePaths)
	if err != nil {
		return nil, warnings, err
	}

	resultMap := make(map[string]interface{})

	// Process found resources
	for k, v := range found {
		if foundMap[k] != "" {
			// Check if resource contains not found error
			if strings.Contains(string(v), "kube-api-error=NotFound") {
				resultMap[foundMap[k]] = &unstructured.Unstructured{}
			} else {
				// Check if k is a subresource
				if strings.HasPrefix(k, "/") {
					// Unmarshal JSON content into an unstructured object
					result := &unstructured.Unstructured{}
					if err := json.Unmarshal(v, result); err != nil {
						return nil, warnings, fmt.Errorf("failed to parse JSON for %s: %v", k, err)
					}
					resultMap[foundMap[k]] = result
				} else {
					// Unmarshal JSON content into an unstructured list
					results := &unstructured.UnstructuredList{}
					if err := json.Unmarshal(v, results); err != nil {
						return nil, warnings, fmt.Errorf("failed to parse JSON for %s: %v", k, err)
					}
					resultMap[foundMap[k]] = results
				}
			}
		}
	}

	// Add variable results
	for k, v := range variableResultMap {
		resultMap[k] = v
	}

	return resultMap, warnings, nil
}

// figureResources is adapted from the original FigureResources method
func (f *ComplianceOperatorResourceFetcher) figureResources(rule *v1alpha1.CustomRule, variables []*v1alpha1.Variable) ([]utils.ResourcePath, map[string]string, map[string]string, error) {
	found := []utils.ResourcePath{}
	foundMap := make(map[string]string)
	variableResultMap := make(map[string]string)

	for _, universalInput := range rule.Spec.Inputs {
		input := universalInput.KubeResource
		gvr := schema.GroupVersionResource{
			Group:    input.APIGroup,
			Version:  input.Version,
			Resource: input.Resource,
		}

		// Check if we have any variables set
		for _, variable := range variables {
			// Check if the gvr is the same as the input
			if gvr.Group == variable.GroupVersionKind().Group && gvr.Version == variable.GroupVersionKind().Version {
				// Check if the resource is the same as the input
				if gvr.Resource == variable.GroupVersionKind().Kind+"/"+variable.Name && input.Namespace == variable.Namespace {
					variableResultMap[input.Name] = variable.Value
				}
			}
		}

		// Derive the resource path using the common function
		objPath := DeriveResourcePath(gvr, input.Namespace)
		found = append(found, utils.ResourcePath{
			ObjPath:  objPath,
			DumpPath: objPath,
		})
		foundMap[objPath] = input.Name
	}

	return found, foundMap, variableResultMap, nil
}

// Helper function to convert v1alpha1.CustomRule slice to Rule slice
func AdaptCustomRules(rules []*v1alpha1.CustomRule) []Rule {
	adapted := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		adapted = append(adapted, &ComplianceOperatorRuleAdapter{Rule: rule})
	}
	return adapted
}

// Helper function to convert v1alpha1.Variable slice to Variable slice
func AdaptVariables(variables []*v1alpha1.Variable) []Variable {
	adapted := make([]Variable, 0, len(variables))
	for _, variable := range variables {
		adapted = append(adapted, &ComplianceOperatorVariableAdapter{Variable: variable})
	}
	return adapted
}

// Helper function to convert CheckResult slice to v1alpha1.ComplianceCheckResult slice
func ConvertToComplianceCheckResults(results []CheckResult) []*v1alpha1.ComplianceCheckResult {
	converted := make([]*v1alpha1.ComplianceCheckResult, 0, len(results))
	for _, result := range results {
		ccr := &v1alpha1.ComplianceCheckResult{
			ID: result.ID,
			ObjectMeta: metav1.ObjectMeta{
				Name:        result.Name,
				Namespace:   result.Namespace,
				Labels:      result.Labels,
				Annotations: result.Annotations,
			},
			Description:  result.Description,
			Rationale:    result.Rationale,
			Severity:     v1alpha1.ComplianceCheckResultSeverity(result.Severity),
			Status:       v1alpha1.ComplianceCheckStatus(result.Status),
			Warnings:     result.Warnings,
			Instructions: result.Instructions,
		}
		converted = append(converted, ccr)
	}
	return converted
}

// resourceFetcherClients is a simplified version of the original struct
type resourceFetcherClients struct {
	clientset *kubernetes.Clientset
	client    runtimeclient.Client
}

// These are placeholders for the original functions that would need to be imported
// In a real implementation, these would be imported from the utils package
var (
	getStreamerFn func(context.Context, resourceFetcherClients, utils.ResourcePath) ([]byte, error)
	fetch         func(context.Context, func(context.Context, resourceFetcherClients, utils.ResourcePath) ([]byte, error), resourceFetcherClients, []utils.ResourcePath) (map[string][]byte, []string, error)
)

// SetResourceFetchingFunctions allows setting the actual resource fetching functions
func SetResourceFetchingFunctions(
	streamerFn func(context.Context, resourceFetcherClients, utils.ResourcePath) ([]byte, error),
	fetchFn func(context.Context, func(context.Context, resourceFetcherClients, utils.ResourcePath) ([]byte, error), resourceFetcherClients, []utils.ResourcePath) (map[string][]byte, []string, error),
) {
	getStreamerFn = streamerFn
	fetch = fetchFn
}
