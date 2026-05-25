package celvalidation

import (
	"fmt"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-sdk/pkg/scanner"
)

// ValidateCELRule compiles and structurally validates a CEL expression
// within a RulePayload. Used by both the Rule and CustomRule controllers.
func ValidateCELRule(name string, payload *v1alpha1.RulePayload) error {
	inputs := payload.ToScannerInputs()

	if err := scanner.CompileCELExpression(payload.Expression, inputs); err != nil {
		return fmt.Errorf("CEL expression compilation failed: %w", err)
	}

	builder := scanner.NewRuleBuilder(name, scanner.RuleTypeCEL)
	for _, input := range inputs {
		builder.WithInput(input)
	}
	builder.SetCelExpression(payload.Expression)

	if payload.Description != "" || payload.Title != "" {
		builder.WithMetadata(&scanner.RuleMetadata{
			Name:        payload.Title,
			Description: payload.Description,
		})
	}

	if _, err := builder.BuildCelRule(); err != nil {
		return fmt.Errorf("CEL rule build validation failed: %w", err)
	}

	return nil
}
