package celvalidation

import (
	"testing"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateCELRule(t *testing.T) {
	tests := []struct {
		name      string
		ruleName  string
		payload   v1alpha1.RulePayload
		wantErr   bool
		errSubstr string
	}{
		{
			name:     "valid CEL rule with single input",
			ruleName: "test-valid-rule",
			payload: v1alpha1.RulePayload{
				Title:       "Valid Rule",
				Description: "A valid CEL rule",
				ScannerType: v1alpha1.ScannerTypeCEL,
				Expression:  "pods.items.size() > 0",
				Inputs: []v1alpha1.InputPayload{{
					Name: "pods",
					KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
						APIVersion: "v1",
						Resource:   "pods",
					},
				}},
			},
			wantErr: false,
		},
		{
			name:     "valid CEL rule with multiple inputs",
			ruleName: "test-multi-input",
			payload: v1alpha1.RulePayload{
				Title:       "Multi Input Rule",
				ScannerType: v1alpha1.ScannerTypeCEL,
				Expression:  "pods.items.size() > 0 && configmaps.items.size() > 0",
				Inputs: []v1alpha1.InputPayload{
					{
						Name: "pods",
						KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
							APIVersion: "v1",
							Resource:   "pods",
						},
					},
					{
						Name: "configmaps",
						KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
							APIVersion: "v1",
							Resource:   "configmaps",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:     "valid CEL rule without metadata",
			ruleName: "no-metadata",
			payload: v1alpha1.RulePayload{
				ScannerType: v1alpha1.ScannerTypeCEL,
				Expression:  "nodes.items.size() >= 3",
				Inputs: []v1alpha1.InputPayload{{
					Name: "nodes",
					KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
						APIVersion: "v1",
						Resource:   "nodes",
					},
				}},
			},
			wantErr: false,
		},
		{
			name:     "invalid CEL syntax",
			ruleName: "bad-syntax",
			payload: v1alpha1.RulePayload{
				ScannerType: v1alpha1.ScannerTypeCEL,
				Expression:  "this is not &&& valid CEL",
				Inputs: []v1alpha1.InputPayload{{
					Name: "pods",
					KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
						APIVersion: "v1",
						Resource:   "pods",
					},
				}},
			},
			wantErr:   true,
			errSubstr: "CEL expression compilation failed",
		},
		{
			name:     "undeclared variable reference",
			ruleName: "undeclared-ref",
			payload: v1alpha1.RulePayload{
				ScannerType: v1alpha1.ScannerTypeCEL,
				Expression:  "undeclaredVar.items.size() > 0",
				Inputs: []v1alpha1.InputPayload{{
					Name: "pods",
					KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
						APIVersion: "v1",
						Resource:   "pods",
					},
				}},
			},
			wantErr:   true,
			errSubstr: "CEL expression compilation failed",
		},
		{
			name:     "empty expression",
			ruleName: "empty-expr",
			payload: v1alpha1.RulePayload{
				ScannerType: v1alpha1.ScannerTypeCEL,
				Expression:  "",
				Inputs: []v1alpha1.InputPayload{{
					Name: "pods",
					KubernetesInputSpec: v1alpha1.KubernetesInputSpec{
						APIVersion: "v1",
						Resource:   "pods",
					},
				}},
			},
			wantErr: true,
		},
		{
			name:     "no inputs rejected by SDK",
			ruleName: "no-inputs",
			payload: v1alpha1.RulePayload{
				ScannerType: v1alpha1.ScannerTypeCEL,
				Expression:  "true",
			},
			wantErr:   true,
			errSubstr: "at least one input is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCELRule(tt.ruleName, &tt.payload)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errSubstr != "" {
					assert.Contains(t, err.Error(), tt.errSubstr)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
