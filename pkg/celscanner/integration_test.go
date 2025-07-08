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
	"testing"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestAdapters_ComplianceOperatorTypes(t *testing.T) {
	// Create a real v1alpha1.CustomRule
	customRule := &v1alpha1.CustomRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rule",
			Namespace: "default",
		},
		Spec: v1alpha1.CustomRuleSpec{
			RulePayload: v1alpha1.RulePayload{
				ID:          "test-001",
				Title:       "Test Rule",
				Description: "Test rule description",
				Severity:    "medium",
			},
			CELPayload: v1alpha1.CELPayload{
				Expression: "pods.items.size() > 0",
				Inputs: []v1alpha1.InputPayload{
					{
						KubeResource: v1alpha1.KubeResource{
							Name:     "pods",
							Type:     v1alpha1.InputResourceTypeKubeResource,
							APIGroup: "",
							Version:  "v1",
							Resource: "pods",
						},
					},
				},
			},
		},
	}

	// Create a real v1alpha1.Variable
	variable := &v1alpha1.Variable{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-var",
			Namespace: "default",
		},
		VariablePayload: v1alpha1.VariablePayload{
			ID:    "var-001",
			Value: "test-value",
			Type:  v1alpha1.VarTypeString,
		},
	}

	// Test adapters
	adaptedRules := AdaptCustomRules([]*v1alpha1.CustomRule{customRule})
	adaptedVariables := AdaptVariables([]*v1alpha1.Variable{variable})

	if len(adaptedRules) != 1 {
		t.Fatalf("Expected 1 adapted rule, got %d", len(adaptedRules))
	}

	if len(adaptedVariables) != 1 {
		t.Fatalf("Expected 1 adapted variable, got %d", len(adaptedVariables))
	}

	// Test rule adapter
	rule := adaptedRules[0]
	if rule.GetName() != "test-rule" {
		t.Errorf("Expected rule name 'test-rule', got '%s'", rule.GetName())
	}
	if rule.GetID() != "test-001" {
		t.Errorf("Expected rule ID 'test-001', got '%s'", rule.GetID())
	}
	if rule.GetExpression() != "pods.items.size() > 0" {
		t.Errorf("Expected expression 'pods.items.size() > 0', got '%s'", rule.GetExpression())
	}

	inputs := rule.GetInputs()
	if len(inputs) != 1 {
		t.Fatalf("Expected 1 input, got %d", len(inputs))
	}

	input := inputs[0]
	if input.GetName() != "pods" {
		t.Errorf("Expected input name 'pods', got '%s'", input.GetName())
	}

	kubeResource := input.GetKubeResource()
	if kubeResource.GetResource() != "pods" {
		t.Errorf("Expected resource 'pods', got '%s'", kubeResource.GetResource())
	}

	// Test variable adapter
	adaptedVar := adaptedVariables[0]
	if adaptedVar.GetName() != "test-var" {
		t.Errorf("Expected variable name 'test-var', got '%s'", adaptedVar.GetName())
	}
	if adaptedVar.GetValue() != "test-value" {
		t.Errorf("Expected variable value 'test-value', got '%s'", adaptedVar.GetValue())
	}
}

func TestIntegration_ScannerWithMockResourceFetcher(t *testing.T) {
	// Create mock resources
	mockPods := createMockPodList()
	mockConfigMaps := createMockConfigMapList()

	// Create mock resource fetcher
	mockFetcher := &MockResourceFetcher{
		resources: map[string]interface{}{
			"pods":       mockPods,
			"configmaps": mockConfigMaps,
		},
	}

	// Create scanner with mock fetcher
	scanner := NewScanner(mockFetcher, &TestLogger{t: t})

	// Create test rules using our test implementations
	rules := []Rule{
		&TestRule{
			name:        "pods-exist",
			id:          "test-001",
			description: "Check if pods exist",
			expression:  "pods.items.size() > 0",
			inputs: []RuleInput{
				&TestRuleInput{
					name: "pods",
					kubeResource: &TestKubeResource{
						name:     "pods",
						resource: "pods",
					},
				},
			},
		},
		&TestRule{
			name:        "configmap-check",
			id:          "test-002",
			description: "Check configmap data",
			expression:  `configmaps.items.exists(cm, cm.metadata.name == "test-config")`,
			inputs: []RuleInput{
				&TestRuleInput{
					name: "configmaps",
					kubeResource: &TestKubeResource{
						name:     "configmaps",
						resource: "configmaps",
					},
				},
			},
		},
	}

	config := ScanConfig{
		Rules: rules,
	}

	// Execute scan
	ctx := context.Background()
	results, err := scanner.Scan(ctx, config)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(results))
	}

	// Verify first result (pods exist)
	if results[0].Status != CheckResultPass {
		t.Errorf("Expected first result to pass, got %s", results[0].Status)
	}

	// Verify second result (configmap check)
	if results[1].Status != CheckResultPass {
		t.Errorf("Expected second result to pass, got %s", results[1].Status)
	}
}

func TestIntegration_ConvertToComplianceCheckResults(t *testing.T) {
	// Create test results
	results := []CheckResult{
		{
			ID:          "test-001",
			Name:        "test-rule-1",
			Namespace:   "default",
			Status:      CheckResultPass,
			Severity:    "medium",
			Description: "Test rule 1",
			Warnings:    []string{"warning 1"},
		},
		{
			ID:          "test-002",
			Name:        "test-rule-2",
			Namespace:   "default",
			Status:      CheckResultFail,
			Severity:    "high",
			Description: "Test rule 2",
		},
	}

	// Convert to compliance check results
	converted := ConvertToComplianceCheckResults(results)

	if len(converted) != 2 {
		t.Fatalf("Expected 2 converted results, got %d", len(converted))
	}

	// Verify first result
	result1 := converted[0]
	if result1.ID != "test-001" {
		t.Errorf("Expected ID 'test-001', got '%s'", result1.ID)
	}
	if result1.Name != "test-rule-1" {
		t.Errorf("Expected name 'test-rule-1', got '%s'", result1.Name)
	}
	if result1.Status != v1alpha1.CheckResultPass {
		t.Errorf("Expected status PASS, got %s", result1.Status)
	}
	if string(result1.Severity) != "medium" {
		t.Errorf("Expected severity 'medium', got '%s'", result1.Severity)
	}
	if len(result1.Warnings) != 1 {
		t.Errorf("Expected 1 warning, got %d", len(result1.Warnings))
	}

	// Verify second result
	result2 := converted[1]
	if result2.Status != v1alpha1.CheckResultFail {
		t.Errorf("Expected status FAIL, got %s", result2.Status)
	}
	if string(result2.Severity) != "high" {
		t.Errorf("Expected severity 'high', got '%s'", result2.Severity)
	}
}

func TestIntegration_RealWorldScenarios(t *testing.T) {
	tests := []struct {
		name         string
		setupMocks   func() *MockResourceFetcher
		rule         Rule
		expectedPass bool
		description  string
	}{
		{
			name: "pod security compliance",
			setupMocks: func() *MockResourceFetcher {
				pods := &unstructured.UnstructuredList{
					Items: []unstructured.Unstructured{
						{
							Object: map[string]interface{}{
								"metadata": map[string]interface{}{
									"name": "secure-pod",
								},
								"spec": map[string]interface{}{
									"securityContext": map[string]interface{}{
										"runAsNonRoot": true,
									},
									"containers": []interface{}{
										map[string]interface{}{
											"name": "container1",
											"securityContext": map[string]interface{}{
												"runAsNonRoot": true,
											},
										},
									},
								},
							},
						},
					},
				}
				return &MockResourceFetcher{
					resources: map[string]interface{}{
						"pods": pods,
					},
				}
			},
			rule: &TestRule{
				name:       "pod-security",
				expression: "pods.items.all(pod, pod.spec.securityContext.runAsNonRoot == true)",
				inputs: []RuleInput{
					&TestRuleInput{
						name: "pods",
						kubeResource: &TestKubeResource{
							name:     "pods",
							resource: "pods",
						},
					},
				},
			},
			expectedPass: true,
			description:  "Should pass when all pods run as non-root",
		},
		{
			name: "network policy enforcement",
			setupMocks: func() *MockResourceFetcher {
				policies := &unstructured.UnstructuredList{
					Items: []unstructured.Unstructured{
						{
							Object: map[string]interface{}{
								"metadata": map[string]interface{}{
									"name":      "deny-all",
									"namespace": "default",
								},
								"spec": map[string]interface{}{
									"podSelector": map[string]interface{}{},
									"policyTypes": []interface{}{"Ingress", "Egress"},
								},
							},
						},
					},
				}
				return &MockResourceFetcher{
					resources: map[string]interface{}{
						"networkpolicies": policies,
					},
				}
			},
			rule: &TestRule{
				name:       "network-policy",
				expression: `networkpolicies.items.exists(policy, policy.metadata.name == "deny-all")`,
				inputs: []RuleInput{
					&TestRuleInput{
						name: "networkpolicies",
						kubeResource: &TestKubeResource{
							name:     "networkpolicies",
							resource: "networkpolicies",
						},
					},
				},
			},
			expectedPass: true,
			description:  "Should pass when required network policy exists",
		},
		{
			name: "resource quota validation",
			setupMocks: func() *MockResourceFetcher {
				quotas := &unstructured.UnstructuredList{
					Items: []unstructured.Unstructured{
						{
							Object: map[string]interface{}{
								"metadata": map[string]interface{}{
									"name":      "compute-quota",
									"namespace": "default",
								},
								"spec": map[string]interface{}{
									"hard": map[string]interface{}{
										"requests.cpu":    "4",
										"requests.memory": "8Gi",
										"limits.cpu":      "8",
										"limits.memory":   "16Gi",
									},
								},
							},
						},
					},
				}
				return &MockResourceFetcher{
					resources: map[string]interface{}{
						"resourcequotas": quotas,
					},
				}
			},
			rule: &TestRule{
				name: "resource-quota",
				expression: `resourcequotas.items.exists(quota, 
					has(quota.spec.hard) && 
					"requests.cpu" in quota.spec.hard && 
					"requests.memory" in quota.spec.hard
				)`,
				inputs: []RuleInput{
					&TestRuleInput{
						name: "resourcequotas",
						kubeResource: &TestKubeResource{
							name:     "resourcequotas",
							resource: "resourcequotas",
						},
					},
				},
			},
			expectedPass: true,
			description:  "Should pass when resource quotas are properly configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFetcher := tt.setupMocks()
			scanner := NewScanner(mockFetcher, &TestLogger{t: t})

			config := ScanConfig{
				Rules: []Rule{tt.rule},
			}

			ctx := context.Background()
			results, err := scanner.Scan(ctx, config)

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(results) != 1 {
				t.Fatalf("Expected 1 result, got %d", len(results))
			}

			result := results[0]
			passed := result.Status == CheckResultPass

			if passed != tt.expectedPass {
				t.Errorf("Test '%s': expected pass=%v, got pass=%v (status=%s)",
					tt.name, tt.expectedPass, passed, result.Status)
			}

			t.Logf("Real-world scenario '%s' completed: %s", tt.name, tt.description)
		})
	}
}

// Mock implementations

type MockResourceFetcher struct {
	resources map[string]interface{}
	warnings  []string
	err       error
}

func (m *MockResourceFetcher) FetchResources(ctx context.Context, rule Rule, variables []Variable) (map[string]interface{}, []string, error) {
	if m.err != nil {
		return nil, nil, m.err
	}

	result := make(map[string]interface{})
	for _, input := range rule.GetInputs() {
		resourceName := input.GetName()
		if resource, exists := m.resources[resourceName]; exists {
			result[resourceName] = resource
		} else {
			// Return empty list for missing resources
			result[resourceName] = &unstructured.UnstructuredList{Items: []unstructured.Unstructured{}}
		}
	}

	return result, m.warnings, nil
}

// Helper functions to create mock data

func createMockPodList() *unstructured.UnstructuredList {
	podData := `{
		"apiVersion": "v1",
		"kind": "PodList",
		"items": [
			{
				"apiVersion": "v1",
				"kind": "Pod",
				"metadata": {
					"name": "test-pod",
					"namespace": "default"
				},
				"spec": {
					"containers": [
						{
							"name": "main",
							"image": "nginx:latest"
						}
					]
				}
			}
		]
	}`

	var podList unstructured.UnstructuredList
	json.Unmarshal([]byte(podData), &podList)
	return &podList
}

func createMockConfigMapList() *unstructured.UnstructuredList {
	configMapData := `{
		"apiVersion": "v1",
		"kind": "ConfigMapList",
		"items": [
			{
				"apiVersion": "v1",
				"kind": "ConfigMap",
				"metadata": {
					"name": "test-config",
					"namespace": "default"
				},
				"data": {
					"key1": "value1",
					"config.json": "{\"enabled\": true}"
				}
			}
		]
	}`

	var configMapList unstructured.UnstructuredList
	json.Unmarshal([]byte(configMapData), &configMapList)
	return &configMapList
}
