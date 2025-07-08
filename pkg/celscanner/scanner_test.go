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
	"os"
	"path/filepath"
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestScanner_Scan_WithMockResources(t *testing.T) {
	tests := []struct {
		name           string
		rules          []Rule
		variables      []Variable
		resourcePath   string
		expectedCount  int
		expectedStatus []CheckResultStatus
		description    string
	}{
		{
			name: "pods exist check",
			rules: []Rule{
				&TestRule{
					name:        "pods-exist",
					id:          "pods-001",
					description: "Check if pods exist in cluster",
					expression:  "pods.items.size() > 0",
					inputs: []RuleInput{
						&TestRuleInput{
							name: "pods",
							kubeResource: &TestKubeResource{
								name:      "pods",
								apiGroup:  "",
								version:   "v1",
								resource:  "pods",
								namespace: "",
							},
						},
					},
				},
			},
			expectedCount:  1,
			expectedStatus: []CheckResultStatus{CheckResultPass},
			description:    "Should pass when pods exist",
		},
		{
			name: "pod security context check",
			rules: []Rule{
				&TestRule{
					name:        "pod-security-context",
					id:          "pods-002",
					description: "Check if all pods run as non-root",
					expression:  "pods.items.all(pod, has(pod.spec.securityContext) && pod.spec.securityContext.runAsNonRoot == true)",
					inputs: []RuleInput{
						&TestRuleInput{
							name: "pods",
							kubeResource: &TestKubeResource{
								name:      "pods",
								apiGroup:  "",
								version:   "v1",
								resource:  "pods",
								namespace: "",
							},
						},
					},
				},
			},
			expectedCount:  1,
			expectedStatus: []CheckResultStatus{CheckResultFail}, // Will fail because some pods don't run as non-root
			description:    "Should fail when not all pods run as non-root",
		},
		{
			name: "resource limits check",
			rules: []Rule{
				&TestRule{
					name:        "resource-limits",
					id:          "pods-003",
					description: "Check if pods have resource limits",
					expression: `pods.items.all(pod, 
						pod.spec.containers.all(container, 
							has(container.resources) && 
							has(container.resources.limits) && 
							has(container.resources.limits.memory) && 
							has(container.resources.limits.cpu)
						)
					)`,
					inputs: []RuleInput{
						&TestRuleInput{
							name: "pods",
							kubeResource: &TestKubeResource{
								name:      "pods",
								apiGroup:  "",
								version:   "v1",
								resource:  "pods",
								namespace: "",
							},
						},
					},
				},
			},
			expectedCount:  1,
			expectedStatus: []CheckResultStatus{CheckResultFail}, // Will fail because not all containers have limits
			description:    "Should fail when not all containers have resource limits",
		},
		{
			name: "configmap data validation",
			rules: []Rule{
				&TestRule{
					name:        "configmap-validation",
					id:          "cm-001",
					description: "Check if configmaps have required data",
					expression:  `configmaps.items.exists(cm, cm.metadata.name == "app-config" && has(cm.data) && "feature.json" in cm.data)`,
					inputs: []RuleInput{
						&TestRuleInput{
							name: "configmaps",
							kubeResource: &TestKubeResource{
								name:      "configmaps",
								apiGroup:  "",
								version:   "v1",
								resource:  "configmaps",
								namespace: "",
							},
						},
					},
				},
			},
			expectedCount:  1,
			expectedStatus: []CheckResultStatus{CheckResultPass},
			description:    "Should pass when required configmap exists with data",
		},
		{
			name: "configmap json parsing",
			rules: []Rule{
				&TestRule{
					name:        "configmap-json-parse",
					id:          "cm-002",
					description: "Check if configmap contains JSON data",
					expression: `configmaps.items.exists(cm, 
						cm.metadata.name == "app-config" && 
						has(cm.data) && 
						"feature.json" in cm.data &&
						cm.data["feature.json"].contains("auth")
					)`,
					inputs: []RuleInput{
						&TestRuleInput{
							name: "configmaps",
							kubeResource: &TestKubeResource{
								name:      "configmaps",
								apiGroup:  "",
								version:   "v1",
								resource:  "configmaps",
								namespace: "",
							},
						},
					},
				},
			},
			expectedCount:  1,
			expectedStatus: []CheckResultStatus{CheckResultPass},
			description:    "Should pass when configmap contains expected JSON content",
		},
		{
			name: "service type validation",
			rules: []Rule{
				&TestRule{
					name:        "service-type-check",
					id:          "svc-001",
					description: "Check if any service is of type LoadBalancer",
					expression:  `services.items.exists(svc, svc.spec.type == "LoadBalancer")`,
					inputs: []RuleInput{
						&TestRuleInput{
							name: "services",
							kubeResource: &TestKubeResource{
								name:      "services",
								apiGroup:  "",
								version:   "v1",
								resource:  "services",
								namespace: "",
							},
						},
					},
				},
			},
			expectedCount:  1,
			expectedStatus: []CheckResultStatus{CheckResultPass},
			description:    "Should pass when LoadBalancer service exists",
		},
		{
			name: "multi-resource validation",
			rules: []Rule{
				&TestRule{
					name:        "pods-and-services",
					id:          "multi-001",
					description: "Check if pods exist and have matching services",
					expression: `pods.items.size() > 0 && services.items.size() > 0 && 
						pods.items.exists(pod, 
							services.items.exists(svc, 
								has(pod.metadata.labels.app) && 
								has(svc.spec.selector.app) && 
								pod.metadata.labels.app == svc.spec.selector.app
							)
						)`,
					inputs: []RuleInput{
						&TestRuleInput{
							name: "pods",
							kubeResource: &TestKubeResource{
								name:      "pods",
								apiGroup:  "",
								version:   "v1",
								resource:  "pods",
								namespace: "",
							},
						},
						&TestRuleInput{
							name: "services",
							kubeResource: &TestKubeResource{
								name:      "services",
								apiGroup:  "",
								version:   "v1",
								resource:  "services",
								namespace: "",
							},
						},
					},
				},
			},
			expectedCount:  1,
			expectedStatus: []CheckResultStatus{CheckResultPass},
			description:    "Should pass when pods have matching services",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test scanner with file-based resource fetcher
			scanner := NewScanner(nil, &TestLogger{t: t})

			// Setup test data directory
			testDataDir := setupTestData(t)

			config := ScanConfig{
				Rules:           tt.rules,
				Variables:       tt.variables,
				ApiResourcePath: testDataDir,
			}

			// Execute scan
			ctx := context.Background()
			results, err := scanner.Scan(ctx, config)

			// Verify results
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(results) != tt.expectedCount {
				t.Fatalf("Expected %d results, got %d", tt.expectedCount, len(results))
			}

			for i, result := range results {
				if i < len(tt.expectedStatus) {
					if result.Status != tt.expectedStatus[i] {
						t.Errorf("Rule %s: expected status %s, got %s",
							result.Name, tt.expectedStatus[i], result.Status)
					}
				}
			}

			t.Logf("Test '%s' completed: %s", tt.name, tt.description)
		})
	}
}

func TestScanner_ErrorHandling(t *testing.T) {
	tests := []struct {
		name           string
		rule           Rule
		expectError    bool
		expectedStatus CheckResultStatus
		description    string
	}{
		{
			name: "invalid CEL expression",
			rule: &TestRule{
				name:       "invalid-expression",
				expression: "invalid.expression.syntax...",
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
			expectError:    false, // Should not fail the scan, but create an ERROR result
			expectedStatus: CheckResultError,
			description:    "Should create ERROR result for invalid CEL expression",
		},
		{
			name: "missing resource reference",
			rule: &TestRule{
				name:       "missing-resource",
				expression: "nonexistent.items.size() > 0",
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
			expectError:    false, // Should not fail the scan, but create an ERROR result
			expectedStatus: CheckResultError,
			description:    "Should create ERROR result for undeclared resource references",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewScanner(nil, &TestLogger{t: t})
			testDataDir := setupTestData(t)

			config := ScanConfig{
				Rules:           []Rule{tt.rule},
				ApiResourcePath: testDataDir,
			}

			ctx := context.Background()
			results, err := scanner.Scan(ctx, config)

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Check that we got a result (even for compilation errors)
			if len(results) != 1 {
				t.Fatalf("Expected 1 result, got %d", len(results))
			}

			result := results[0]
			if result.Status != tt.expectedStatus {
				t.Errorf("Expected status %s, got %s", tt.expectedStatus, result.Status)
			}

			// For error results, check that detailed information is provided
			if result.Status == CheckResultError {
				if len(result.Warnings) == 0 {
					t.Errorf("Expected error warnings but got none")
				}
				if result.Annotations["error.type"] != "compilation" {
					t.Errorf("Expected error.type annotation to be 'compilation', got '%s'", result.Annotations["error.type"])
				}
				if result.Annotations["cel.expression"] == "" {
					t.Errorf("Expected cel.expression annotation to be set")
				}

				t.Logf("Error details: %s", result.Annotations["error.detail"])
				t.Logf("Available resources: %s", result.Annotations["available.resources"])
				t.Logf("Declared inputs: %s", result.Annotations["declared.inputs"])
			}

			t.Logf("Error handling test '%s' completed: %s", tt.name, tt.description)
		})
	}
}

func TestScanner_WithVariables(t *testing.T) {
	// Test with variables
	rule := &TestRule{
		name:        "configmap-with-variable",
		id:          "var-001",
		description: "Test rule with variables",
		expression:  `configmaps.items.exists(cm, cm.metadata.name == configName)`,
		inputs: []RuleInput{
			&TestRuleInput{
				name: "configmaps",
				kubeResource: &TestKubeResource{
					name:     "configmaps",
					resource: "configmaps",
				},
			},
		},
	}

	variables := []Variable{
		&TestVariable{
			name:  "configName",
			value: "app-config",
		},
	}

	scanner := NewScanner(nil, &TestLogger{t: t})
	testDataDir := setupTestData(t)

	config := ScanConfig{
		Rules:           []Rule{rule},
		Variables:       variables,
		ApiResourcePath: testDataDir,
	}

	ctx := context.Background()
	results, err := scanner.Scan(ctx, config)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Note: This test would pass if variable substitution was implemented
	// For now, it demonstrates the test structure
	t.Logf("Variable test completed - result status: %s", results[0].Status)
}

func TestSaveResults(t *testing.T) {
	results := []CheckResult{
		{
			ID:          "test-001",
			Name:        "test-rule",
			Status:      CheckResultPass,
			Description: "Test rule description",
		},
	}

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "test_results.json")

	err := SaveResults(filePath, results)
	if err != nil {
		t.Fatalf("SaveResults failed: %v", err)
	}

	// Verify file exists and has correct content
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read results file: %v", err)
	}

	var savedResults []CheckResult
	err = json.Unmarshal(data, &savedResults)
	if err != nil {
		t.Fatalf("Failed to unmarshal results: %v", err)
	}

	if len(savedResults) != 1 {
		t.Fatalf("Expected 1 saved result, got %d", len(savedResults))
	}

	if savedResults[0].ID != "test-001" {
		t.Errorf("Expected ID 'test-001', got '%s'", savedResults[0].ID)
	}
}

// setupTestData creates test data directory with mock resources
func setupTestData(t *testing.T) string {
	testDataDir := t.TempDir()

	// Copy test resource files to temp directory
	copyTestResource(t, "testdata/pods.json", filepath.Join(testDataDir, "pods.json"))
	copyTestResource(t, "testdata/configmaps.json", filepath.Join(testDataDir, "configmaps.json"))
	copyTestResource(t, "testdata/services.json", filepath.Join(testDataDir, "services.json"))

	// Create namespace-specific directories
	namespacesDir := filepath.Join(testDataDir, "namespaces", "default")
	err := os.MkdirAll(namespacesDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create namespaces directory: %v", err)
	}

	copyTestResource(t, "testdata/namespaces/default/pods.json",
		filepath.Join(namespacesDir, "pods.json"))

	return testDataDir
}

// copyTestResource copies a test resource file
func copyTestResource(t *testing.T, src, dst string) {
	srcData, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("Failed to read test resource %s: %v", src, err)
	}

	err = os.WriteFile(dst, srcData, 0644)
	if err != nil {
		t.Fatalf("Failed to write test resource %s: %v", dst, err)
	}
}

// Test implementations of interfaces

type TestRule struct {
	name         string
	namespace    string
	id           string
	description  string
	rationale    string
	severity     string
	instructions string
	title        string
	errorMessage string
	expression   string
	inputs       []RuleInput
}

func (r *TestRule) GetName() string         { return r.name }
func (r *TestRule) GetNamespace() string    { return r.namespace }
func (r *TestRule) GetID() string           { return r.id }
func (r *TestRule) GetDescription() string  { return r.description }
func (r *TestRule) GetRationale() string    { return r.rationale }
func (r *TestRule) GetSeverity() string     { return r.severity }
func (r *TestRule) GetInstructions() string { return r.instructions }
func (r *TestRule) GetTitle() string        { return r.title }
func (r *TestRule) GetErrorMessage() string { return r.errorMessage }
func (r *TestRule) GetExpression() string   { return r.expression }
func (r *TestRule) GetInputs() []RuleInput  { return r.inputs }

type TestRuleInput struct {
	name         string
	kubeResource KubeResource
}

func (i *TestRuleInput) GetName() string               { return i.name }
func (i *TestRuleInput) GetKubeResource() KubeResource { return i.kubeResource }

type TestKubeResource struct {
	name      string
	apiGroup  string
	version   string
	resource  string
	namespace string
}

func (k *TestKubeResource) GetName() string      { return k.name }
func (k *TestKubeResource) GetAPIGroup() string  { return k.apiGroup }
func (k *TestKubeResource) GetVersion() string   { return k.version }
func (k *TestKubeResource) GetResource() string  { return k.resource }
func (k *TestKubeResource) GetNamespace() string { return k.namespace }

type TestVariable struct {
	name      string
	namespace string
	value     string
	gvk       schema.GroupVersionKind
}

func (v *TestVariable) GetName() string                              { return v.name }
func (v *TestVariable) GetNamespace() string                         { return v.namespace }
func (v *TestVariable) GetValue() string                             { return v.value }
func (v *TestVariable) GetGroupVersionKind() schema.GroupVersionKind { return v.gvk }

type TestLogger struct {
	t *testing.T
}

func (l *TestLogger) Debug(msg string, args ...interface{}) {
	l.t.Logf("[DEBUG] "+msg, args...)
}

func (l *TestLogger) Info(msg string, args ...interface{}) {
	l.t.Logf("[INFO] "+msg, args...)
}

func (l *TestLogger) Warn(msg string, args ...interface{}) {
	l.t.Logf("[WARN] "+msg, args...)
}

func (l *TestLogger) Error(msg string, args ...interface{}) {
	l.t.Logf("[ERROR] "+msg, args...)
}
