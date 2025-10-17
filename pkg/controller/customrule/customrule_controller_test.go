package customrule

import (
	"context"
	"testing"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis"
	"github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestCustomRuleReconciler_Reconcile(t *testing.T) {
	// Register types with the scheme
	s := scheme.Scheme
	apis.AddToScheme(s)

	tests := []struct {
		name           string
		rule           *v1alpha1.CustomRule
		expectedPhase  string
		expectError    bool
		expectedErrMsg string
	}{
		{
			name: "Valid CustomRule with simple CEL expression",
			rule: &v1alpha1.CustomRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "valid-rule",
					Namespace:  "test",
					Generation: 1,
				},
				Spec: v1alpha1.CustomRuleSpec{
					RulePayload: v1alpha1.RulePayload{
						ID:          "test-rule-1",
						Title:       "Test Rule",
						Description: "A test rule for validation",
						Severity:    "medium",
					},
					CELPayload: v1alpha1.CELPayload{
						ScannerType: v1alpha1.ScannerTypeCEL,
						Expression:  "pods.items.all(pod, pod.spec.containers.all(container, container.securityContext.runAsNonRoot == true))",
						Inputs: []v1alpha1.InputPayload{
							{
								KubeResource: v1alpha1.KubeResource{
									Name: "pods",
									KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
										Group:      "",
										APIVersion: "v1",
										Resource:   "pods",
									},
								},
							},
						},
						ErrorMessage: "All containers must run as non-root",
					},
				},
			},
			expectedPhase: v1alpha1.CustomRulePhaseReady,
			expectError:   false,
		},
		{
			name: "Invalid CustomRule with empty CEL expression",
			rule: &v1alpha1.CustomRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "invalid-empty-expression",
					Namespace:  "test",
					Generation: 1,
				},
				Spec: v1alpha1.CustomRuleSpec{
					RulePayload: v1alpha1.RulePayload{
						ID:          "test-rule-2",
						Title:       "Invalid Rule",
						Description: "A rule with empty expression",
						Severity:    "high",
					},
					CELPayload: v1alpha1.CELPayload{
						ScannerType:  v1alpha1.ScannerTypeCEL,
						Expression:   "", // Empty expression
						Inputs:       []v1alpha1.InputPayload{},
						ErrorMessage: "This should fail",
					},
				},
			},
			expectedPhase:  v1alpha1.CustomRulePhaseError,
			expectError:    false,
			expectedErrMsg: "structure validation failed: CEL expression is empty",
		},
		{
			name: "Valid CustomRule with multiple inputs",
			rule: &v1alpha1.CustomRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "valid-multi-input",
					Namespace:  "test",
					Generation: 1,
				},
				Spec: v1alpha1.CustomRuleSpec{
					RulePayload: v1alpha1.RulePayload{
						ID:          "test-rule-5",
						Title:       "Multi-input Rule",
						Description: "A rule with multiple inputs",
						Severity:    "medium",
					},
					CELPayload: v1alpha1.CELPayload{
						ScannerType: v1alpha1.ScannerTypeCEL,
						Expression:  "namespaces.items.all(ns, networkpolicies.items.exists(np, np.metadata.namespace == ns.metadata.name))",
						Inputs: []v1alpha1.InputPayload{
							{
								KubeResource: v1alpha1.KubeResource{
									Name: "namespaces",
									KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
										Group:      "",
										APIVersion: "v1",
										Resource:   "namespaces",
									},
								},
							},
							{
								KubeResource: v1alpha1.KubeResource{
									Name: "networkpolicies",
									KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
										Group:      "networking.k8s.io",
										APIVersion: "v1",
										Resource:   "networkpolicies",
									},
								},
							},
						},
						ErrorMessage: "All namespaces must have network policies",
					},
				},
			},
			expectedPhase: v1alpha1.CustomRulePhaseReady,
			expectError:   false,
		},
		{
			name: "Invalid CustomRule with missing required fields",
			rule: &v1alpha1.CustomRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "invalid-missing-fields",
					Namespace:  "test",
					Generation: 1,
				},
				Spec: v1alpha1.CustomRuleSpec{
					RulePayload: v1alpha1.RulePayload{
						ID:          "test-rule-6",
						Title:       "Incomplete Rule",
						Description: "A rule with missing required fields",
						Severity:    "medium",
					},
					CELPayload: v1alpha1.CELPayload{
						ScannerType: v1alpha1.ScannerTypeCEL,
						Expression:  "true",
						Inputs: []v1alpha1.InputPayload{
							{
								KubeResource: v1alpha1.KubeResource{
									Name: "test",
									KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
										// Missing APIVersion and Resource
										Group: "apps",
									},
								},
							},
						},
						ErrorMessage: "This should fail validation",
					},
				},
			},
			expectedPhase:  v1alpha1.CustomRulePhaseError,
			expectError:    false,
			expectedErrMsg: "structure validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fake client with the rule
			fakeClient := fake.NewClientBuilder().
				WithScheme(s).
				WithRuntimeObjects(tt.rule).
				WithStatusSubresource(tt.rule).
				Build()

			// Create reconciler
			r := &CustomRuleReconciler{
				Client: fakeClient,
				Scheme: s,
			}

			// Create reconcile request
			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      tt.rule.Name,
					Namespace: tt.rule.Namespace,
				},
			}

			// Perform reconciliation
			ctx := context.Background()
			result, err := r.Reconcile(ctx, req)

			// Check error expectation
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Check that the rule status was updated
			updatedRule := &v1alpha1.CustomRule{}
			err = fakeClient.Get(ctx, req.NamespacedName, updatedRule)
			require.NoError(t, err)

			// Verify status fields
			assert.Equal(t, tt.expectedPhase, updatedRule.Status.Phase, "Phase should match expected")

			if tt.expectedErrMsg != "" {
				assert.Contains(t, updatedRule.Status.ErrorMessage, tt.expectedErrMsg, "Error message should contain expected text")
			}

			// Check that ObservedGeneration was updated
			assert.Equal(t, tt.rule.Generation, updatedRule.Status.ObservedGeneration, "ObservedGeneration should be updated")

			// Check that LastValidationTime was set
			assert.NotNil(t, updatedRule.Status.LastValidationTime, "LastValidationTime should be set")

			// For error cases, check requeue
			if tt.expectedPhase == v1alpha1.CustomRulePhaseError {
				assert.True(t, result.RequeueAfter > 0, "Failed validation should trigger requeue")
			}
		})
	}
}

func TestCustomRuleReconciler_ValidateStructure(t *testing.T) {
	r := &CustomRuleReconciler{}

	tests := []struct {
		name        string
		rule        *v1alpha1.CustomRule
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid structure",
			rule: &v1alpha1.CustomRule{
				Spec: v1alpha1.CustomRuleSpec{
					CELPayload: v1alpha1.CELPayload{
						Expression: "true",
						Inputs: []v1alpha1.InputPayload{
							{
								KubeResource: v1alpha1.KubeResource{
									Name: "test",
									KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
										APIVersion: "v1",
										Resource:   "pods",
									},
								},
							},
						},
						ErrorMessage: "test error",
					},
				},
			},
			expectError: false,
		},
		{
			name: "Empty expression",
			rule: &v1alpha1.CustomRule{
				Spec: v1alpha1.CustomRuleSpec{
					CELPayload: v1alpha1.CELPayload{
						Expression: "",
						Inputs: []v1alpha1.InputPayload{
							{
								KubeResource: v1alpha1.KubeResource{
									Name: "test",
								},
							},
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "CEL expression is empty",
		},
		{
			name: "No inputs",
			rule: &v1alpha1.CustomRule{
				Spec: v1alpha1.CustomRuleSpec{
					CELPayload: v1alpha1.CELPayload{
						Expression: "true",
						Inputs:     []v1alpha1.InputPayload{},
					},
				},
			},
			expectError: true,
			errorMsg:    "no inputs defined",
		},
		{
			name: "Input with empty name",
			rule: &v1alpha1.CustomRule{
				Spec: v1alpha1.CustomRuleSpec{
					CELPayload: v1alpha1.CELPayload{
						Expression: "true",
						Inputs: []v1alpha1.InputPayload{
							{
								KubeResource: v1alpha1.KubeResource{
									Name: "",
									KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
										APIVersion: "v1",
										Resource:   "pods",
									},
								},
							},
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "empty variable name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := r.validateStructure(tt.rule)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
