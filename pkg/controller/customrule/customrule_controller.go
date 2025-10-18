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

package customrule

import (
	"context"
	"fmt"
	"time"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-sdk/pkg/scanner"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// CustomRuleReconciler reconciles a CustomRule object
type CustomRuleReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=compliance.openshift.io,resources=customrules,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=compliance.openshift.io,resources=customrules/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=compliance.openshift.io,resources=customrules/finalizers,verbs=update

// Reconcile is the main reconciliation loop for CustomRule resources
func (r *CustomRuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.Info("Reconciling CustomRule")

	// Fetch the CustomRule instance
	rule := &v1alpha1.CustomRule{}
	err := r.Get(ctx, req.NamespacedName, rule)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Return and don't requeue
			log.Info("CustomRule resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		log.Error(err, "Failed to get CustomRule")
		return ctrl.Result{}, err
	}

	// Check if the rule has already been validated for the current generation
	if rule.Status.ObservedGeneration == rule.Generation && rule.Status.Phase == v1alpha1.CustomRulePhaseReady {
		log.Info("CustomRule already validated for current generation", "generation", rule.Generation)
		return ctrl.Result{}, nil
	}

	// Validate and compile CEL expression using SDK's RuleBuilder
	// Basic field validation is already handled by kubebuilder annotations
	var validationErr error
	if err := r.validateCELExpressionWithBuilder(rule); err != nil {
		validationErr = err
	}

	// Update status based on validation results
	now := metav1.NewTime(time.Now())
	rule.Status.LastValidationTime = &now
	rule.Status.ObservedGeneration = rule.Generation

	if validationErr != nil {
		// Validation failed
		rule.Status.Phase = v1alpha1.CustomRulePhaseError
		rule.Status.ErrorMessage = validationErr.Error()
	} else {
		// Validation succeeded
		rule.Status.Phase = v1alpha1.CustomRulePhaseReady
		rule.Status.ErrorMessage = ""
	}

	// Update the status
	if err := r.Status().Update(ctx, rule); err != nil {
		log.Error(err, "Failed to update CustomRule status")
		return ctrl.Result{}, err
	}

	log.Info("Successfully reconciled CustomRule", "phase", rule.Status.Phase)

	// If there was a validation error, requeue after a delay to retry
	if validationErr != nil {
		return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
	}

	return ctrl.Result{}, nil
}

// validateCELExpressionWithBuilder validates the CEL expression using SDK's validation
func (r *CustomRuleReconciler) validateCELExpressionWithBuilder(rule *v1alpha1.CustomRule) error {
	if err := rule.Validate(); err != nil {
		return fmt.Errorf("CustomRule validation failed: %w", err)
	}

	// Use the SDK's validation functionality directly
	// Convert CustomRule inputs to SDK inputs for validation
	inputs := make([]scanner.Input, 0, len(rule.Spec.CustomRulePayload.Inputs))
	for _, input := range rule.Spec.CustomRulePayload.Inputs {
		spec := &input.KubernetesInputSpec

		// Create a Kubernetes input using the SDK's constructor
		// The CustomRule's KubernetesInputSpec implements the interface
		sdkInput := &scanner.InputImpl{
			InputName: input.Name,
			InputType: scanner.InputTypeKubernetes,
			InputSpec: spec,
		}
		inputs = append(inputs, sdkInput)
	}

	// Use the new validation API to validate the CEL expression
	err := scanner.CompileCELExpression(rule.Spec.CustomRulePayload.Expression, inputs)
	if err != nil {
		return fmt.Errorf("CEL expression validation failed: %w", err)
	}

	// Also use RuleBuilder for additional validation
	builder := scanner.NewRuleBuilder(rule.Name, scanner.RuleTypeCEL)
	for _, input := range inputs {
		builder.WithInput(input)
	}
	builder.SetCelExpression(rule.Spec.CustomRulePayload.Expression)

	// Add metadata if available
	if rule.Spec.Description != "" || rule.Spec.Title != "" {
		metadata := &scanner.RuleMetadata{
			Name:        rule.Spec.Title,
			Description: rule.Spec.Description,
		}
		builder.WithMetadata(metadata)
	}

	// Try to build the rule - this provides additional structural validation
	_, buildErr := builder.BuildCelRule()
	if buildErr != nil {
		return fmt.Errorf("rule building validation failed: %w", buildErr)
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager
func (r *CustomRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.CustomRule{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1, // Process one at a time for now
		}).
		Complete(r)
}

// Add creates a new CustomRule Controller and adds it to the Manager
func Add(mgr ctrl.Manager) error {
	return (&CustomRuleReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr)
}
