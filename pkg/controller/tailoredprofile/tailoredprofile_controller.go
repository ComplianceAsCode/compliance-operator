package tailoredprofile

import (
	"context"
	"fmt"
	"strings"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/metrics"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"

	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/common"
	"github.com/ComplianceAsCode/compliance-operator/pkg/xccdf"
	"github.com/go-logr/logr"

	cmpv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var log = logf.Log.WithName("tailoredprofilectrl")

const (
	tailoringFile string = "tailoring.xml"
)

func (r *ReconcileTailoredProfile) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmpv1alpha1.TailoredProfile{}).
		Complete(r)
}

// Add creates a new TailoredProfile Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, met *metrics.Metrics, _ utils.CtlplaneSchedulingInfo, _ *kubernetes.Clientset) error {
	return add(mgr, newReconciler(mgr, met))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, met *metrics.Metrics) reconcile.Reconciler {
	return &ReconcileTailoredProfile{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), Metrics: met, Recorder: common.NewSafeRecorder("tailoredprofile-controller", mgr)}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	varMapper := &variableMapper{mgr.GetClient()}
	ruleMapper := &ruleMapper{mgr.GetClient()}
	customRuleMapper := &customRuleMapper{mgr.GetClient()}
	return ctrl.NewControllerManagedBy(mgr).
		Named("tailoredprofile-controller").
		For(&cmpv1alpha1.TailoredProfile{}).
		Owns(&corev1.ConfigMap{}).
		Watches(&cmpv1alpha1.Variable{}, handler.EnqueueRequestsFromMapFunc(varMapper.Map)).
		Watches(&cmpv1alpha1.Rule{}, handler.EnqueueRequestsFromMapFunc(ruleMapper.Map)).
		Watches(&cmpv1alpha1.CustomRule{}, handler.EnqueueRequestsFromMapFunc(customRuleMapper.Map)).
		Complete(r)
}

// blank assignment to verify that ReconcileTailoredProfile implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileTailoredProfile{}

func (r *ReconcileTailoredProfile) Eventf(object runtime.Object, eventtype, reason, messageFmt string, args ...interface{}) {
	if r.Recorder == nil {
		return
	}

	r.Recorder.Eventf(object, eventtype, reason, messageFmt, args...)
}

// ReconcileTailoredProfile reconciles a TailoredProfile object
type ReconcileTailoredProfile struct {
	// This Client, initialized using mgr.Client() above, is a split Client
	// that reads objects from the cache and writes to the apiserver
	Client   client.Client
	Scheme   *runtime.Scheme
	Metrics  *metrics.Metrics
	Recorder *common.SafeRecorder
}

// Reconcile reads that state of the cluster for a TailoredProfile object and makes changes based on the state read
// and what is in the TailoredProfile.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileTailoredProfile) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling TailoredProfile")

	// Fetch the TailoredProfile instance
	instance := &cmpv1alpha1.TailoredProfile{}
	err := r.Client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		if kerrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	var pb *cmpv1alpha1.ProfileBundle
	var p *cmpv1alpha1.Profile

	customRules, err := r.getCustomRulesFromSelections(instance)
	if err != nil && !common.IsRetriable(err) {
		// the Profile or ProfileBundle objects didn't exist, or CustomRule validation failed. Surface the error.
		err = r.handleTailoredProfileStatusError(instance, err)
		return reconcile.Result{}, err
	} else if err != nil {
		// This is a retriable error (e.g., CustomRule not ready yet)
		reqLogger.Info("CustomRules not ready, requeueing", "error", err.Error())
		// Requeue after a short delay to check again
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Check if TailoredProfile mixes CustomRules and regular Rules
	if err := r.validateNoMixedRuleTypes(instance, customRules); err != nil {
		err = r.handleTailoredProfileStatusError(instance, err)
		return reconcile.Result{}, err
	}

	if instance.Spec.Extends != "" {
		// make sure we don't have any custom rules, as they are not supported with extends
		if len(customRules) > 0 {
			err = r.handleTailoredProfileStatusError(instance, fmt.Errorf("Custom rules are not supported with extends"))
			return reconcile.Result{}, err
		}
		var pbgetErr error
		p, pb, pbgetErr = r.getProfileInfoFromExtends(instance)
		if pbgetErr != nil && !common.IsRetriable(pbgetErr) {
			// the Profile or ProfileBundle objects didn't exist. Surface the error.
			err = r.handleTailoredProfileStatusError(instance, pbgetErr)
			return reconcile.Result{}, err
		} else if pbgetErr != nil {
			return reconcile.Result{}, pbgetErr
		}

		needsAnnotation := false

		if instance.GetAnnotations() == nil {
			needsAnnotation = true
		} else {
			if _, ok := instance.GetAnnotations()[cmpv1alpha1.ProductTypeAnnotation]; !ok {
				needsAnnotation = true
			}
		}

		if needsAnnotation {
			tpCopy := instance.DeepCopy()
			anns := tpCopy.GetAnnotations()
			if anns == nil {
				anns = make(map[string]string)
			}

			scanType := utils.GetScanType(p.GetAnnotations())
			anns[cmpv1alpha1.ProductTypeAnnotation] = string(scanType)
			anns[cmpv1alpha1.ScannerTypeAnnotation] = string(cmpv1alpha1.ScannerTypeOpenSCAP)
			tpCopy.SetAnnotations(anns)

			// Set labels for the TailoredProfile
			labels := tpCopy.GetLabels()
			if labels == nil {
				labels = make(map[string]string)
			}
			labels[cmpv1alpha1.ProfileGuidLabel] = xccdf.GetProfileUniqueIDFromTP(xccdf.GetXCCDFProfileID(instance))

			labels[cmpv1alpha1.ExtendedProfileGuidLabel] = p.GetLabels()[cmpv1alpha1.ProfileGuidLabel]
			tpCopy.SetLabels(labels)
			// Make TailoredProfile be owned by the Profile it extends. This way
			// we can ensure garbage collection happens.
			// This update will trigger a requeue with the new object.
			if needsControllerRef(tpCopy) {
				return r.setOwnership(tpCopy, p)
			} else {
				r.Client.Update(context.TODO(), tpCopy)
				return reconcile.Result{}, nil
			}
		}

		// If we still need a controller ref, set it now (unless it's CEL, see below)
		if needsControllerRef(instance) {
			tpCopy := instance.DeepCopy()
			return r.setOwnership(tpCopy, p)
		}

		// Warn that TailoredProfile extends deprecated Profile
		if p.GetAnnotations()[cmpv1alpha1.ProfileStatusAnnotation] == "deprecated" {
			reqLogger.Info("TailoredProfile extends a deprecated profile", instance.Name, p.Name)
			r.Recorder.Eventf(
				instance, corev1.EventTypeWarning, "DeprecatedTailoredProfile",
				"TailoredProfile %s is extending a deprecated Profile (%s) that will be removed in a future version of Compliance Operator. "+
					"Please consider using a newer version of this profile", instance.Name, p.Name)
		}

	} else {
		if !isValidationRequired(instance) {
			// check if the TailoredProfile is empty without any extends
			// if it is empty, we should not update the tp, and set the state of tp to Error
			err = r.handleTailoredProfileStatusError(instance, fmt.Errorf("Custom TailoredProfile with no extends does not have any rules enabled"))
			if err != nil {
				return reconcile.Result{}, err
			}
			return reconcile.Result{}, nil
		}

		// we will not use ProfileBundle for CustomRules
		if len(customRules) == 0 {
			reqLogger.Info("No Custom Rules found for TailoredProfile", "tailoredProfile", instance.GetName())
			var pbgetErr error
			pb, pbgetErr = r.getProfileBundleFromRulesOrVars(instance)
			if pbgetErr != nil && !common.IsRetriable(pbgetErr) {
				// the Profile or ProfileBundle objects didn't exist. Surface the error.
				err = r.handleTailoredProfileStatusError(instance, pbgetErr)
				return reconcile.Result{}, err
			} else if pbgetErr != nil {
				return reconcile.Result{}, pbgetErr
			}
			// Make TailoredProfile be owned by the ProfileBundle. This way
			// we can ensure garbage collection happens.
			// This update will trigger a requeue with the new object.
			// We will skip this if a customRule is being used.
			if needsControllerRef(instance) {
				tpCopy := instance.DeepCopy()
				anns := tpCopy.GetAnnotations()
				if anns == nil {
					anns = make(map[string]string)
				}
				// If the user already provided the product type, we
				// don't need to set it
				_, ok := anns[cmpv1alpha1.ProductTypeAnnotation]
				if !ok {
					if strings.HasSuffix(tpCopy.GetName(), "-node") {
						anns[cmpv1alpha1.ProductTypeAnnotation] = string(cmpv1alpha1.ScanTypeNode)
					} else {
						anns[cmpv1alpha1.ProductTypeAnnotation] = string(cmpv1alpha1.ScanTypePlatform)
					}
					tpCopy.SetAnnotations(anns)
				}
				// This will trigger an update anyway
				return r.setOwnership(tpCopy, pb)
			}
		}

		if len(customRules) > 0 {
			reqLogger.Info("Custom rules detected, skipping ProfileBundle and setting product type to platform")
			// we are detection custom rules, we will not use ProfileBundle, and at the moment we only support platform type

			needsAnnotation := false

			if instance.GetAnnotations() == nil {
				needsAnnotation = true
			} else {
				if productType, ok := instance.GetAnnotations()[cmpv1alpha1.ProductTypeAnnotation]; !ok || productType != string(cmpv1alpha1.ScanTypePlatform) {
					needsAnnotation = true
				}
				if ScannerType, ok := instance.GetAnnotations()[cmpv1alpha1.ScannerTypeAnnotation]; !ok || ScannerType != string(cmpv1alpha1.ScannerTypeCEL) {
					needsAnnotation = true
				}
				if hasCutomRule, ok := instance.GetAnnotations()[cmpv1alpha1.CustomRuleProfileAnnotation]; !ok || hasCutomRule != "true" {
					needsAnnotation = true
				}
			}

			if needsAnnotation {
				tpCopy := instance.DeepCopy()
				anns := tpCopy.GetAnnotations()
				if anns == nil {
					anns = make(map[string]string)
				}
				// TODO: @Vincent056 we should possibly remove this in the future
				// and use a dynamic approach to set the product type and scanner type
				scanType := cmpv1alpha1.ScanTypePlatform
				anns[cmpv1alpha1.ProductTypeAnnotation] = string(scanType)
				anns[cmpv1alpha1.ScannerTypeAnnotation] = string(cmpv1alpha1.ScannerTypeCEL)
				anns[cmpv1alpha1.CustomRuleProfileAnnotation] = "true"
				tpCopy.SetAnnotations(anns)

				// Set labels for the TailoredProfile
				labels := tpCopy.GetLabels()
				if labels == nil {
					labels = make(map[string]string)
				}
				labels[cmpv1alpha1.ProfileGuidLabel] = xccdf.GetProfileUniqueIDFromTP(xccdf.GetXCCDFProfileID(instance))

				tpCopy.SetLabels(labels)
				// update the TailoredProfile
				return reconcile.Result{}, r.Client.Update(context.TODO(), tpCopy)
			}
			_, err := r.getCustomVariablesFromSelections(instance)
			if err != nil && !common.IsRetriable(err) {
				// the variables didn't exist. Surface the error.
				err = r.handleTailoredProfileStatusError(instance, err)
				return reconcile.Result{}, err
			} else if err != nil {
				return reconcile.Result{}, err
			}
		}
	}

	ann := instance.GetAnnotations()
	// we will skip all pruning if custom rules are used
	if v, ok := ann[cmpv1alpha1.DisableOutdatedReferenceValidation]; ok && v == "true" || len(customRules) > 0 {
		reqLogger.Info("Reference validation is disabled or custom rules are used, skipping validation")
	} else if isValidationRequired(instance) {
		reqLogger.Info("Validating TailoredProfile")
		pruneOutdated := false
		if v, ok := ann[cmpv1alpha1.PruneOutdatedReferencesAnnotationKey]; ok && v == "true" {
			pruneOutdated = true
		}

		// handle deprecated rules here in the future

		doContinue, ruleNeedToBeMigratedList, err := r.handleRulePruning(instance, reqLogger, pruneOutdated)
		if err != nil {
			return reconcile.Result{}, err
		}
		if !doContinue {
			return reconcile.Result{}, nil
		}

		warningMsg := generateWarningMessage(ruleNeedToBeMigratedList)
		// check if warning message matches the previous warning message
		// if it does, we don't need to update the tp, if not we need to update it with the new warning message
		if warningMsg != instance.Status.Warnings {
			tpCopy := instance.DeepCopy()
			tpCopy.Status.Warnings = warningMsg
			r.Client.Status().Update(context.TODO(), tpCopy)
		}

	}

	// we should do the following only if the tailored profile does not have CustomRules
	if len(customRules) <= 0 {
		rules, ruleErr := r.getRulesFromSelections(instance, pb)
		if ruleErr != nil && !common.IsRetriable(ruleErr) {
			// Surface the error.
			suerr := r.handleTailoredProfileStatusError(instance, ruleErr)
			return reconcile.Result{}, suerr
		} else if ruleErr != nil {
			return reconcile.Result{}, ruleErr
		}

		if ruleValidErr := assertValidRuleTypes(rules); ruleValidErr != nil {
			// Surface the error.
			suerr := r.handleTailoredProfileStatusError(instance, ruleValidErr)
			return reconcile.Result{}, suerr
		}

		variables, varErr := r.getVariablesFromSelections(instance, pb)
		if varErr != nil && !common.IsRetriable(varErr) {
			// Surface the error.
			suerr := r.handleTailoredProfileStatusError(instance, varErr)
			return reconcile.Result{}, suerr
		} else if varErr != nil {
			return reconcile.Result{}, varErr
		}
		tpcm := newTailoredProfileCM(instance)

		tpcm.Data[tailoringFile], err = xccdf.TailoredProfileToXML(instance, p, pb, rules, variables)
		if err != nil {
			return reconcile.Result{}, err
		}
		return r.ensureOutputObject(instance, tpcm, reqLogger)
	}
	if len(customRules) > 0 {
		// use dummy tpcm for custom rules
		// TODO:@Vincent056 we should possibly remove this in the future
		tpcm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      instance.Name,
				Namespace: instance.Namespace,
			},
		}

		// Log successful validation of CustomRules
		reqLogger.Info("All CustomRules are validated and ready", "count", len(customRules))

		err = r.updateTailoredProfileStatusReady(instance, tpcm)
		if err != nil {
			reqLogger.Error(err, "Couldn't update TailoredProfile status")
			return reconcile.Result{}, err
		}
	}

	// @Vincent056 TODO: We should possibly add customVariables for CustomRules, also make sure
	// that if a tailored profile is using custom rules, it should not use any variables as it
	// will not do anything

	return reconcile.Result{}, nil
}

// generateWarningMessage generates a warning message for the user
// based on the list of deprecated variables and rules that are detected
// as well as the list of migrated rules that are detected that are not
// migrated yet
func generateWarningMessage(ruleNeedToBeMigratedList []string) string {
	var warningMessage string
	if len(ruleNeedToBeMigratedList) > 0 {
		if warningMessage != "" {
			warningMessage = fmt.Sprintf("%sThe following rules changed check type and need to be removed from the TailoredProfile. If these rules are important for you, add them to a TailoredProfile of matching check type: %s\n", warningMessage, strings.Join(ruleNeedToBeMigratedList, ","))
		} else {
			warningMessage = fmt.Sprintf("The following rules changed check type and need to be removed from the TailoredProfile. If these rules are important for you, add them to a TailoredProfile of matching check type: %s\n", strings.Join(ruleNeedToBeMigratedList, ","))
		}
	}
	return warningMessage
}

// handleRulePruning check if there are any migrated rules in the TailoredProfile
// and we will handle the migration of the tailored profile accordingly
func (r *ReconcileTailoredProfile) handleRulePruning(
	v1alphaTp *cmpv1alpha1.TailoredProfile, logger logr.Logger, pruneOudated bool) (doContinue bool, ruleNeedToBeMigratedList []string, err error) {
	doContinue = true
	// Get the list of KubeletConfig rules that are migrated with checkType change
	migratedRules, err := r.getMigratedRules(v1alphaTp, logger)
	if err != nil {
		return false, nil, err
	}

	if len(migratedRules) == 0 {
		return true, nil, nil
	}

	profileType := utils.GetScanType(v1alphaTp.GetAnnotations())

	v1alphaTpCP := v1alphaTp.DeepCopy()

	// check if there are any disabled rules that are migrated
	if len(v1alphaTp.Spec.DisableRules) > 0 {
		var newRules []cmpv1alpha1.RuleReferenceSpec
		for ri := range v1alphaTp.Spec.DisableRules {
			rule := &v1alphaTp.Spec.DisableRules[ri]
			if checkType, ok := migratedRules[rule.Name]; ok && checkType != string(profileType) {
				// remove the rule from the list of disabled rules
				if pruneOudated {
					doContinue = false
					logger.Info("Removing migrated rule from disableRules", "rule", rule.Name)
					r.Eventf(v1alphaTp, corev1.EventTypeWarning, "TailoredProfileMigratedRule", "Removing migrated rule: %s from disableRules, it has been changed from %s to %s", rule.Name, checkType, profileType)
				} else {
					logger.Info("Migrated rule detected in disableRules", "rule", rule.Name)
					r.Eventf(v1alphaTp, corev1.EventTypeWarning, "TailoredProfileMigratedRule", "%s type changed from %s to %s. Please migrate it or remove it from the TailoredProfile", rule.Name, checkType, profileType)
					ruleNeedToBeMigratedList = append(ruleNeedToBeMigratedList, rule.Name)
					newRules = append(newRules, *rule)
				}
				continue
			}
			newRules = append(newRules, *rule)
		}
		if len(newRules) != len(v1alphaTp.Spec.DisableRules) {
			v1alphaTpCP.Spec.DisableRules = newRules
		}
	}

	// check if there are any enabled rules that are migrated
	if len(v1alphaTp.Spec.EnableRules) > 0 {
		var newRules []cmpv1alpha1.RuleReferenceSpec
		for ri := range v1alphaTp.Spec.EnableRules {
			rule := &v1alphaTp.Spec.EnableRules[ri]
			if checkType, ok := migratedRules[rule.Name]; ok && checkType != string(profileType) {
				if pruneOudated {
					doContinue = false
					logger.Info("Removing migrated rule from enableRules", "rule", rule.Name)
					r.Eventf(v1alphaTp, corev1.EventTypeWarning, "TailoredProfileMigratedRule", "Removing migrated rule %s from enableRules, it has been changed from %s to %s", rule.Name, checkType, profileType)
				} else {
					logger.Info("Migrated rule detected in enableRules", "rule", rule.Name)
					r.Eventf(v1alphaTp, corev1.EventTypeWarning, "TailoredProfileMigratedRule", "%s type changed from %s to %s. Please migrate it or remove it from the TailoredProfile", rule.Name, checkType, profileType)
					ruleNeedToBeMigratedList = append(ruleNeedToBeMigratedList, rule.Name)
					newRules = append(newRules, *rule)
				}
				continue
			}
			newRules = append(newRules, *rule)
		}

		if len(newRules) != len(v1alphaTp.Spec.EnableRules) {
			v1alphaTpCP.Spec.EnableRules = newRules
		}
	}

	if v1alphaTp.Spec.Extends == "" && len(v1alphaTpCP.Spec.DisableRules) == 0 && len(v1alphaTpCP.Spec.EnableRules) == 0 {
		errorMsg := "TailoredProfile does not have any rules left after removing migrated rules and it does not extend any profile"
		v1alphaTpCP.Status.State = cmpv1alpha1.TailoredProfileStateError
		v1alphaTpCP.Status.ErrorMessage = errorMsg
		doContinue = false
		logger.Info(errorMsg)
		r.Eventf(v1alphaTp, corev1.EventTypeWarning, "TailoredProfileMigratedRule", errorMsg)
	}

	if !doContinue {
		err = r.Client.Update(context.TODO(), v1alphaTpCP)
		logger.Info("Updating TailoredProfile after handling migration")
		if err != nil {
			return false, nil, err
		}
	}
	return doContinue, ruleNeedToBeMigratedList, nil
}

func isValidationRequired(tp *cmpv1alpha1.TailoredProfile) bool {
	if tp.Spec.Extends != "" {
		return tp.Spec.DisableRules != nil || tp.Spec.EnableRules != nil || tp.Spec.ManualRules != nil || tp.Spec.SetValues != nil
	}
	return tp.Spec.EnableRules != nil || tp.Spec.ManualRules != nil || tp.Spec.SetValues != nil
}

// getMigratedRules get list of rules and check if it has RuleLastCheckTypeChangedAnnotationKey annotation
// if it does, add it to the map with the current check type
func (r *ReconcileTailoredProfile) getMigratedRules(tp *cmpv1alpha1.TailoredProfile, logger logr.Logger) (map[string]string, error) {
	// get all the rules in the namespace
	ruleList := &cmpv1alpha1.RuleList{}
	err := r.Client.List(context.TODO(), ruleList, &client.ListOptions{
		Namespace: tp.GetNamespace(),
	})
	if err != nil {
		return nil, err
	}

	// get all the rules that are migrated
	migratedRules := make(map[string]string)
	for ri := range ruleList.Items {
		rule := &ruleList.Items[ri]
		if rule.Annotations != nil {
			if _, ok := rule.Annotations[cmpv1alpha1.RuleLastCheckTypeChangedAnnotationKey]; ok {
				if rule.CheckType == cmpv1alpha1.CheckTypeNone {
					logger.Info("Rule has been changed to manual check", "rule", rule.GetName())
					r.Eventf(tp, corev1.EventTypeWarning, "TailoredProfileMigratedRule", "Rule has been changed to manual check: %s", rule.GetName())
					continue
				}
				migratedRules[rule.GetName()] = rule.CheckType
			}
		}
	}
	return migratedRules, nil
}

// getProfileInfoFromExtends gets the Profile and ProfileBundle where the rules come from
// out of the profile that's being extended
func (r *ReconcileTailoredProfile) getProfileInfoFromExtends(tp *cmpv1alpha1.TailoredProfile) (*cmpv1alpha1.Profile, *cmpv1alpha1.ProfileBundle, error) {
	p := &cmpv1alpha1.Profile{}
	// Get the Profile being extended
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: tp.Spec.Extends, Namespace: tp.Namespace}, p)
	if kerrors.IsNotFound(err) {
		return nil, nil, common.NewNonRetriableCtrlError("fetching profile to be extended: %w", err)
	}
	if err != nil {
		return nil, nil, err
	}

	pb, err := r.getProfileBundleFrom("Profile", p)
	if err != nil {
		return nil, nil, err
	}

	return p, pb, nil
}

// getProfileBundleFromRulesOrVars gets the ProfileBundle where the rules come from
func (r *ReconcileTailoredProfile) getProfileBundleFromRulesOrVars(tp *cmpv1alpha1.TailoredProfile) (*cmpv1alpha1.ProfileBundle, error) {
	var ruleToBeChecked *cmpv1alpha1.Rule
	for _, selection := range append(tp.Spec.EnableRules, append(tp.Spec.DisableRules, tp.Spec.ManualRules...)...) {
		rule := &cmpv1alpha1.Rule{}
		ruleKey := types.NamespacedName{Name: selection.Name, Namespace: tp.Namespace}
		geterr := r.Client.Get(context.TODO(), ruleKey, rule)
		if geterr != nil {
			// We'll validate this later in the Reconcile loop
			if kerrors.IsNotFound(geterr) {
				continue
			}
			return nil, geterr
		}
		ruleToBeChecked = rule
		break
	}
	if ruleToBeChecked != nil {
		pb, err := r.getProfileBundleFrom("Rule", ruleToBeChecked)
		if err != nil {
			return nil, err
		}

		return pb, nil
	}

	var varToBeChecked *cmpv1alpha1.Variable
	for _, setValues := range tp.Spec.SetValues {
		variable := &cmpv1alpha1.Variable{}
		varKey := types.NamespacedName{Name: setValues.Name, Namespace: tp.Namespace}
		err := r.Client.Get(context.TODO(), varKey, variable)
		if err != nil {
			// We'll verify this later in the reconcile loop
			if kerrors.IsNotFound(err) {
				continue
			}
			return nil, err
		}

		varToBeChecked = variable
		break
	}

	if varToBeChecked != nil {
		pb, err := r.getProfileBundleFrom("Variable", varToBeChecked)
		if err != nil {
			return nil, err
		}

		return pb, nil
	}

	return nil, common.NewNonRetriableCtrlError("Unable to get ProfileBundle from selected rules and variables")
}

func (r *ReconcileTailoredProfile) getRulesFromSelections(tp *cmpv1alpha1.TailoredProfile, pb *cmpv1alpha1.ProfileBundle) (map[string]*cmpv1alpha1.Rule, error) {
	rules := make(map[string]*cmpv1alpha1.Rule, len(tp.Spec.EnableRules)+len(tp.Spec.DisableRules)+len(tp.Spec.ManualRules))
	ruleKind := cmpv1alpha1.RuleKind
	for _, selection := range append(tp.Spec.EnableRules, append(tp.Spec.DisableRules, tp.Spec.ManualRules...)...) {
		if selection.Kind != ruleKind && selection.Kind != "" {
			continue
		}
		_, ok := rules[selection.Name]
		if ok {
			return nil, common.NewNonRetriableCtrlError("Rule '%s' appears twice in selections (enableRules or disableRules or manualRules)", selection.Name)
		}
		// make sure all rules have the same scanner type
		if selection.Kind != "" && selection.Kind != ruleKind {
			return nil, common.NewNonRetriableCtrlError("Rule '%s' has unsupported Type: %s, compliance operator does not support multiple types of rules in a single TailoredProfile", selection.Name, selection.Kind)
		}

		rule := &cmpv1alpha1.Rule{}
		ruleKey := types.NamespacedName{Name: selection.Name, Namespace: tp.Namespace}
		err := r.Client.Get(context.TODO(), ruleKey, rule)
		if err != nil {
			if kerrors.IsNotFound(err) {
				return nil, common.NewNonRetriableCtrlError("Fetching rule: %w", err)
			}
			return nil, err
		}

		// All variables should be part of the same ProfileBundle
		if !isOwnedBy(rule, pb) {
			return nil, common.NewNonRetriableCtrlError("rule %s not owned by expected ProfileBundle %s",
				rule.GetName(), pb.GetName())
		}

		rules[selection.Name] = rule
	}
	return rules, nil
}

func (r *ReconcileTailoredProfile) getCustomRulesFromSelections(tp *cmpv1alpha1.TailoredProfile) (map[string]*cmpv1alpha1.CustomRule, error) {
	rules := make(map[string]*cmpv1alpha1.CustomRule, len(tp.Spec.EnableRules)+len(tp.Spec.DisableRules)+len(tp.Spec.ManualRules))
	ruleKind := cmpv1alpha1.CustomRuleKind
	for _, selection := range append(tp.Spec.EnableRules, append(tp.Spec.DisableRules, tp.Spec.ManualRules...)...) {
		// Skip non-CustomRule selections (Kind must be explicitly set to CustomRule)
		if selection.Kind != ruleKind {
			continue
		}
		_, ok := rules[selection.Name]
		if ok {
			return nil, common.NewNonRetriableCtrlError("Rule '%s' appears twice in selections (enableRules or disableRules or manualRules)", selection.Name)
		}
		rule := &cmpv1alpha1.CustomRule{}
		ruleKey := types.NamespacedName{Name: selection.Name, Namespace: tp.Namespace}
		err := r.Client.Get(context.TODO(), ruleKey, rule)
		if err != nil {
			if kerrors.IsNotFound(err) {
				return nil, common.NewNonRetriableCtrlError("Fetching rule: %w", err)
			}
			return nil, err
		}

		// Make sure all CustomRule has ScannerType as CEL as we only support CEL at this time
		if rule.Spec.ScannerType != cmpv1alpha1.ScannerTypeCEL {
			return nil, common.NewNonRetriableCtrlError("CustomRule '%s' has unsupported ScannerType: %s", rule.Name, rule.Spec.ScannerType)
		}

		// Check if the CustomRule is ready (validated)
		if rule.Status.Phase != cmpv1alpha1.CustomRulePhaseReady {
			if rule.Status.Phase == cmpv1alpha1.CustomRulePhaseError {
				return nil, common.NewNonRetriableCtrlError("CustomRule '%s' has validation errors: %s", rule.Name, rule.Status.ErrorMessage)
			}
			// If the rule is not ready yet (perhaps still being validated), return a retriable error
			// This will cause the TailoredProfile to be requeued
			// Note: plain errors are retriable by default in this codebase
			return nil, fmt.Errorf("CustomRule '%s' is not ready yet", rule.Name)
		}

		rules[selection.Name] = rule
	}
	return rules, nil
}

// validateNoMixedRuleTypes ensures that a TailoredProfile doesn't mix CustomRules and regular Rules
func (r *ReconcileTailoredProfile) validateNoMixedRuleTypes(tp *cmpv1alpha1.TailoredProfile, customRules map[string]*cmpv1alpha1.CustomRule) error {
	// If we have CustomRules, check if there are any regular Rules
	if len(customRules) > 0 {
		hasRegularRules := false
		var regularRuleNames []string
		var customRuleNames []string

		for _, selection := range append(tp.Spec.EnableRules, append(tp.Spec.DisableRules, tp.Spec.ManualRules...)...) {
			// If Kind is empty or explicitly set to "Rule", it's a regular rule
			if selection.Kind == "" || selection.Kind == cmpv1alpha1.RuleKind {
				hasRegularRules = true
				regularRuleNames = append(regularRuleNames, selection.Name)
			} else if selection.Kind == cmpv1alpha1.CustomRuleKind {
				customRuleNames = append(customRuleNames, selection.Name)
			}
		}

		if hasRegularRules {
			return common.NewNonRetriableCtrlError(
				"TailoredProfile cannot mix CustomRules and regular Rules. Found %d CustomRules (%v) and %d regular Rules (%v). Please use either CustomRules or regular Rules, not both",
				len(customRuleNames), customRuleNames, len(regularRuleNames), regularRuleNames,
			)
		}
	}

	// Also check the reverse case: if we have regular rules with Kind explicitly set to CustomRule
	// This is already handled by getCustomRulesFromSelections() but let's be explicit

	return nil
}

// getCustomVariablesFromSelections is for getting all avaiable variables for CustomRule
func (r *ReconcileTailoredProfile) getCustomVariablesFromSelections(tp *cmpv1alpha1.TailoredProfile) ([]*cmpv1alpha1.Variable, error) {
	variableList := []*cmpv1alpha1.Variable{}
	for _, setValues := range tp.Spec.SetValues {
		variable := &cmpv1alpha1.Variable{}
		varKey := types.NamespacedName{Name: setValues.Name, Namespace: tp.Namespace}
		err := r.Client.Get(context.TODO(), varKey, variable)
		if err != nil {
			if kerrors.IsNotFound(err) {
				return nil, common.NewNonRetriableCtrlError("fetching variable: %w", err)
			}
			return nil, err
		}

		// try setting the variable, this also validates the value
		err = variable.SetValue(setValues.Value)
		if err != nil {
			return nil, common.NewNonRetriableCtrlError("setting variable: %s", err)
		}

		variableList = append(variableList, variable)
	}
	return variableList, nil
}
func (r *ReconcileTailoredProfile) getVariablesFromSelections(tp *cmpv1alpha1.TailoredProfile, pb *cmpv1alpha1.ProfileBundle) ([]*cmpv1alpha1.Variable, error) {
	// First pass: Build de-duplicated map of variables, keeping last occurrence when duplicates exist.
	variables := make(map[string]string)

	for i, setValue := range tp.Spec.SetValues {
		if oldVal, seen := variables[setValue.Name]; seen {
			// We found a duplicate. Warn that we will ignore the previous usage.
			r.Eventf(tp, corev1.EventTypeWarning,
				"DuplicatedSetValue",
				"Variable '%s' appears multiple times in setValues. The operator will keep the last usage with value '%s' (position %d), ignoring the previous value '%s'. Specifying a variable multiple times using setValues will fail in a future release. Please remove duplicates from setValues as it introduces ambiguity.",
				setValue.Name, setValue.Value, i, oldVal)
		}
		// Always use the last occurrence's value
		variables[setValue.Name] = setValue.Value
	}

	// Second pass: Retrieve Variables from cluster and set their values
	// Variables are processed in random order (map iteration)
	variableList := make([]*cmpv1alpha1.Variable, 0, len(variables))
	for varName, value := range variables {
		// Grab the Variable from the cluster
		variable := &cmpv1alpha1.Variable{}
		varKey := types.NamespacedName{Name: varName, Namespace: tp.Namespace}
		if err := r.Client.Get(context.TODO(), varKey, variable); err != nil {
			if kerrors.IsNotFound(err) {
				return nil, common.NewNonRetriableCtrlError("fetching variable: %w", err)
			}
			return nil, err
		}

		// All variables should be part of the same ProfileBundle
		if !isOwnedBy(variable, pb) {
			return nil, common.NewNonRetriableCtrlError("variable %s not owned by expected ProfileBundle %s",
				variable.GetName(), pb.GetName())
		}

		// try setting the variable, this also validates the value
		if err := variable.SetValue(value); err != nil {
			return nil, common.NewNonRetriableCtrlError("setting variable: %s", err)
		}

		variableList = append(variableList, variable)
	}
	return variableList, nil
}

func (r *ReconcileTailoredProfile) updateTailoredProfileStatusReady(tp *cmpv1alpha1.TailoredProfile, out metav1.Object) error {
	// Never update the original (update the copy)
	tpCopy := tp.DeepCopy()
	tpCopy.Status.State = cmpv1alpha1.TailoredProfileStateReady
	tpCopy.Status.ErrorMessage = ""
	tpCopy.Status.OutputRef = cmpv1alpha1.OutputRef{
		Name:      out.GetName(),
		Namespace: out.GetNamespace(),
	}
	tpCopy.Status.ID = xccdf.GetXCCDFProfileID(tp)
	return r.Client.Status().Update(context.TODO(), tpCopy)
}

func (r *ReconcileTailoredProfile) handleTailoredProfileStatusError(tp *cmpv1alpha1.TailoredProfile, err error) error {
	if delErr := r.deleteOutputObject(tp); delErr != nil {
		return delErr
	}

	return r.updateTailoredProfileStatusError(tp, err)
}

func (r *ReconcileTailoredProfile) updateTailoredProfileStatusError(tp *cmpv1alpha1.TailoredProfile, err error) error {
	// Never update the original (update the copy)
	tpCopy := tp.DeepCopy()
	tpCopy.Status.State = cmpv1alpha1.TailoredProfileStateError
	tpCopy.Status.ErrorMessage = err.Error()
	return r.Client.Status().Update(context.TODO(), tpCopy)
}

func (r *ReconcileTailoredProfile) getProfileBundleFrom(objtype string, o metav1.Object) (*cmpv1alpha1.ProfileBundle, error) {
	pbRef, err := getProfileBundleReference(objtype, o)
	if err != nil {
		return nil, err
	}

	pb := cmpv1alpha1.ProfileBundle{}
	// we use the profile's namespace as either way the object's have to be in the same namespace
	// in order for OwnerReferences to work
	err = r.Client.Get(context.TODO(), types.NamespacedName{Name: pbRef.Name, Namespace: o.GetNamespace()}, &pb)
	return &pb, err
}

func (r *ReconcileTailoredProfile) deleteOutputObject(tp *cmpv1alpha1.TailoredProfile) error {
	// make sure the configMap is removed so that we don't keep using the old one after
	// breaking the TP
	tpcm := newTailoredProfileCM(tp)
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: tpcm.Name, Namespace: tpcm.Namespace}, tpcm)
	if err != nil && kerrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return err
	}

	err = r.Client.Delete(context.TODO(), tpcm)
	if err != nil && !kerrors.IsNotFound(err) {
		return err
	}

	return nil
}

func (r *ReconcileTailoredProfile) ensureOutputObject(tp *cmpv1alpha1.TailoredProfile, tpcm *corev1.ConfigMap, logger logr.Logger) (reconcile.Result, error) {
	// Set TailoredProfile instance as the owner and controller
	if err := controllerutil.SetControllerReference(tp, tpcm, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ConfigMap already exists
	found := &corev1.ConfigMap{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: tpcm.Name, Namespace: tpcm.Namespace}, found)
	if err != nil && kerrors.IsNotFound(err) {
		// update status
		err = r.updateTailoredProfileStatusReady(tp, tpcm)
		if err != nil {
			logger.Error(err, "Couldn't update TailoredProfile status")
			return reconcile.Result{}, err
		}

		// create CM
		logger.Info("Creating a new ConfigMap", "ConfigMap.Namespace", tpcm.Namespace, "ConfigMap.Name", tpcm.Name)
		err = r.Client.Create(context.TODO(), tpcm)
		if err != nil {
			return reconcile.Result{}, err
		}

		// ConfigMap created successfully - don't requeue
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// ConfigMap already exists - update
	update := found.DeepCopy()
	update.Data = tpcm.Data
	err = r.Client.Update(context.TODO(), update)
	if err != nil {
		logger.Error(err, "Couldn't update TailoredProfile configMap")
		return reconcile.Result{}, err
	}

	logger.Info("Skip reconcile: ConfigMap already exists and is up-to-date", "ConfigMap.Namespace", found.Namespace, "ConfigMap.Name", found.Name)
	return reconcile.Result{}, nil
}

func (r *ReconcileTailoredProfile) setOwnership(tp *cmpv1alpha1.TailoredProfile, obj metav1.Object) (reconcile.Result, error) {
	if err := controllerutil.SetControllerReference(obj, tp, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}
	err := r.Client.Update(context.TODO(), tp)
	return reconcile.Result{}, err
}

func getProfileBundleReference(objtype string, o metav1.Object) (*metav1.OwnerReference, error) {
	for _, ref := range o.GetOwnerReferences() {
		if ref.Kind == "ProfileBundle" && ref.APIVersion == cmpv1alpha1.SchemeGroupVersion.String() {
			return ref.DeepCopy(), nil
		}
	}
	return nil, fmt.Errorf("%s '%s' had no owning ProfileBundle", objtype, o.GetName())
}

// newTailoredProfileCM creates a tailored profile XML inside a configmap
func newTailoredProfileCM(tp *cmpv1alpha1.TailoredProfile) *corev1.ConfigMap {
	labels := map[string]string{
		"tailored-profile": tp.Name,
	}
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      tp.Name + "-tp",
			Namespace: tp.Namespace,
			Labels:    labels,
		},
		Data: map[string]string{
			tailoringFile: "",
		},
	}
}

func needsControllerRef(obj metav1.Object) bool {
	refs := obj.GetOwnerReferences()
	for _, ref := range refs {
		if ref.Controller != nil {
			if *ref.Controller {
				return false
			}
		}
	}
	return true
}

func isOwnedBy(obj, owner metav1.Object) bool {
	refs := obj.GetOwnerReferences()
	for _, ref := range refs {
		if ref.UID == owner.GetUID() && ref.Name == owner.GetName() {
			return true
		}
	}
	return false
}

func assertValidRuleTypes(rules map[string]*cmpv1alpha1.Rule) error {
	// Figure out
	var expectedCheckType string
	for _, rule := range rules {
		// cmpv1alpha1.CheckTypeNone fits every type since it's
		// merely informational
		if rule.CheckType == cmpv1alpha1.CheckTypeNone {
			continue
		}
		// check if the rule is a migrated rule and if it is, we should not check the type
		if _, ok := rule.Annotations[cmpv1alpha1.RuleLastCheckTypeChangedAnnotationKey]; ok {
			continue
		}
		// Initialize expected check type
		if expectedCheckType == "" {
			expectedCheckType = rule.CheckType
			// No need to compare if we're just initializing the
			// expectation
			continue
		}

		if expectedCheckType != rule.CheckType {
			return common.NewNonRetriableCtrlError("Rule '%s' with type '%s' didn't match expected type: %s",
				rule.GetName(), rule.CheckType, expectedCheckType)
		}
	}
	return nil
}
