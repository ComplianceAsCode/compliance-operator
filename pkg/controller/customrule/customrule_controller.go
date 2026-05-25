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
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils/celvalidation"
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

	var validationErr error
	if err := rule.Validate(); err != nil {
		validationErr = fmt.Errorf("CustomRule validation failed: %w", err)
	} else if err := celvalidation.ValidateCELRule(rule.Name, &rule.Spec.RulePayload); err != nil {
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
