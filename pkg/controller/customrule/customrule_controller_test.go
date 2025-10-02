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
					CustomRulePayload: v1alpha1.CustomRulePayload{
						ScannerType: v1alpha1.ScannerTypeCEL,
						Expression:  "pods.items.all(pod, pod.spec.containers.all(container, container.securityContext.runAsNonRoot == true))",
						Inputs: []v1alpha1.InputPayload{
							{
								Name: "pods",
								KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
									Group:      "",
									APIVersion: "v1",
									Resource:   "pods",
								},
							},
						},
						FailureReason: "All containers must run as non-root",
					},
				},
			},
			expectedPhase: v1alpha1.CustomRulePhaseReady,
			expectError:   false,
		},
		{
			name: "Invalid CustomRule with invalid CEL syntax",
			rule: &v1alpha1.CustomRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "invalid-cel-syntax",
					Namespace:  "test",
					Generation: 1,
				},
				Spec: v1alpha1.CustomRuleSpec{
					RulePayload: v1alpha1.RulePayload{
						ID:          "test-rule-2",
						Title:       "Invalid Rule",
						Description: "A rule with invalid CEL syntax",
						Severity:    "high",
					},
					CustomRulePayload: v1alpha1.CustomRulePayload{
						ScannerType: v1alpha1.ScannerTypeCEL,
						Expression:  "this is not &&& valid CEL syntax", // Invalid CEL syntax
						Inputs: []v1alpha1.InputPayload{
							{
								Name: "test",
								KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
									APIVersion: "v1",
									Resource:   "pods",
								},
							},
						},
						FailureReason: "This should fail",
					},
				},
			},
			expectedPhase:  v1alpha1.CustomRulePhaseError,
			expectError:    false,
			expectedErrMsg: "CEL expression validation failed",
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
					CustomRulePayload: v1alpha1.CustomRulePayload{
						ScannerType: v1alpha1.ScannerTypeCEL,
						Expression:  "namespaces.items.all(ns, networkpolicies.items.exists(np, np.metadata.namespace == ns.metadata.name))",
						Inputs: []v1alpha1.InputPayload{
							{
								Name: "namespaces",
								KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
									Group:      "",
									APIVersion: "v1",
									Resource:   "namespaces",
								},
							},
							{
								Name: "networkpolicies",
								KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
									Group:      "networking.k8s.io",
									APIVersion: "v1",
									Resource:   "networkpolicies",
								},
							},
						},
						FailureReason: "All namespaces must have network policies",
					},
				},
			},
			expectedPhase: v1alpha1.CustomRulePhaseReady,
			expectError:   false,
		},
		{
			name: "Valid CustomRule with multiple inputs and missing one input",
			rule: &v1alpha1.CustomRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "valid-multi-input-missing-one-input",
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
					CustomRulePayload: v1alpha1.CustomRulePayload{
						ScannerType: v1alpha1.ScannerTypeCEL,
						Expression:  "namespaces.items.all(ns, networkpolicies-non-existent.items.exists(np, np.metadata.namespace == ns.metadata.name))",
						Inputs: []v1alpha1.InputPayload{
							{
								Name: "namespaces",
								KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
									Group:      "",
									APIVersion: "v1",
									Resource:   "namespaces",
								},
							},
							{
								Name: "networkpolicies",
								KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
									Group:      "networking.k8s.io",
									APIVersion: "v1",
									Resource:   "networkpolicies",
								},
							},
						},
						FailureReason: "All namespaces must have network policies",
					},
				},
			},
			expectedPhase: v1alpha1.CustomRulePhaseError,
			expectError:   false,
		},
		{
			name: "Invalid CustomRule with undefined input reference in expression",
			rule: &v1alpha1.CustomRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "invalid-undefined-reference",
					Namespace:  "test",
					Generation: 1,
				},
				Spec: v1alpha1.CustomRuleSpec{
					RulePayload: v1alpha1.RulePayload{
						ID:          "test-rule-6",
						Title:       "Undefined Reference Rule",
						Description: "A rule referencing undefined inputs",
						Severity:    "medium",
					},
					CustomRulePayload: v1alpha1.CustomRulePayload{
						ScannerType: v1alpha1.ScannerTypeCEL,
						Expression:  "undefinedInput.items.size() > 0", // References 'undefinedInput' not in inputs
						Inputs: []v1alpha1.InputPayload{
							{
								Name: "test",
								KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
									APIVersion: "v1",
									Resource:   "pods",
								},
							},
						},
						FailureReason: "This should fail validation",
					},
				},
			},
			expectedPhase:  v1alpha1.CustomRulePhaseError,
			expectError:    false,
			expectedErrMsg: "CEL expression validation failed",
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
