package compliancescan

import (
	"context"
	goerrors "errors"
	"fmt"
	"io/ioutil"
	"math"
	"strconv"
	"strings"
	"time"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/common"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/metrics"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
	"github.com/ComplianceAsCode/compliance-operator/pkg/xccdf"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var log = logf.Log.WithName("scanctrl")

var oneReplica int32 = 1

var (
	trueVal     = true
	hostPathDir = corev1.HostPathDirectory
)

const (
	// flag that indicates that deletion should be done
	doDelete = true
	// flag that indicates that no deletion should take place
	dontDelete        = false
	podTimeoutDisable = time.Duration(0)
)

const (
	// OpenSCAPScanContainerName defines the name of the contianer that will run OpenSCAP
	OpenSCAPScanContainerName = "scanner"
	// ContainerName defines the name of the container that will run CEL
	CELScannerContainerName = "cel-scanner"
	// The default time we should wait before requeuing
	requeueAfterDefault = 10 * time.Second
)

func (r *ReconcileComplianceScan) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&compv1alpha1.ComplianceScan{}).
		Complete(r)
}

// Add creates a new ComplianceScan Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, met *metrics.Metrics, si utils.CtlplaneSchedulingInfo, kubeClient *kubernetes.Clientset) error {
	return add(mgr, newReconciler(mgr, met, si, kubeClient))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, met *metrics.Metrics, si utils.CtlplaneSchedulingInfo, kubeClient *kubernetes.Clientset) reconcile.Reconciler {
	return &ReconcileComplianceScan{
		Client:         mgr.GetClient(),
		ClientSet:      kubeClient,
		Scheme:         mgr.GetScheme(),
		Recorder:       mgr.GetEventRecorderFor("scanctrl"),
		Metrics:        met,
		schedulingInfo: si,
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("compliancescan-controller").
		For(&compv1alpha1.ComplianceScan{}).
		Complete(r)
}

// blank assignment to verify that ReconcileComplianceScan implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileComplianceScan{}

// ReconcileComplianceScan reconciles a ComplianceScan object
type ReconcileComplianceScan struct {
	// This Client, initialized using mgr.Client() above, is a split Client
	// that reads objects from the cache and writes to the apiserver
	Client    client.Client
	ClientSet *kubernetes.Clientset
	Scheme    *runtime.Scheme
	Recorder  record.EventRecorder
	Metrics   *metrics.Metrics
	// helps us schedule platform scans on the nodes labeled for the
	// compliance operator's control plane
	schedulingInfo utils.CtlplaneSchedulingInfo
}

// Permissions for all controllers (this means the `compliance-operator` roles and SA). When a controller needs permissions,
// add them here and NOT in config/rbac, and controller-gen will update the files based on this.
//
//+kubebuilder:rbac:groups="",resources=persistentvolumeclaims,persistentvolumes,verbs=watch,create,get,list,delete
//+kubebuilder:rbac:groups="",resources=pods,configmaps,events,verbs=create,get,list,watch,patch,update,delete,deletecollection
//+kubebuilder:rbac:groups="",resources=secrets,verbs=create,get,list,update,watch,delete
//+kubebuilder:rbac:groups="",resources=nodes,nodes/proxy,verbs=get,list,watch
//+kubebuilder:rbac:groups=apps,resources=replicasets,deployments,verbs=get,list,watch,create,update,delete
//+kubebuilder:rbac:groups=compliance.openshift.io,resources=compliancescans,verbs=create,watch,patch,get,list
//+kubebuilder:rbac:groups=compliance.openshift.io,resources=*,verbs=*
//+kubebuilder:rbac:groups=apps,resourceNames=compliance-operator,resources=deployments/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=services,services/finalizers,verbs=create,get,update,delete
//+kubebuilder:rbac:groups=monitoring.coreos.com,resources=servicemonitors,verbs=get,create,update
//+kubebuilder:rbac:groups=apps,resourceNames=compliance-operator,resources=deployments/finalizers,verbs=update
//+kubebuilder:rbac:groups=batch,resources=cronjobs,verbs=get,list,watch,create,delete,update
//+kubebuilder:rbac:groups=batch,resources=jobs,verbs=deletecollection
//+kubebuilder:rbac:groups=image.openshift.io,resources=imagestreamtags,verbs=get,list,watch
//+kubebuilder:rbac:groups=scheduling.k8s.io,resources=priorityclasses,verbs=get,list,watch
//+kubebuilder:rbac:groups=cluster.open-cluster-management.io,resources=clusterclaims,verbs=get,list,watch
//+kubebuilder:rbac:groups=config.openshift.io,resources=infrastructures,verbs=get,list,watch

// Reconcile reads that state of the cluster for a ComplianceScan object and makes changes based on the state read
// and what is in the ComplianceScan.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileComplianceScan) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling ComplianceScan")

	// Fetch the ComplianceScan instance
	instance := &compv1alpha1.ComplianceScan{}
	err := r.Client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	// examine DeletionTimestamp to determine if object is under deletion
	if instance.ObjectMeta.DeletionTimestamp.IsZero() {
		// The object is not being deleted, so if it does not have our finalizer,
		// then lets add the finalizer and update the object. This is equivalent
		// registering our finalizer.
		if !common.ContainsFinalizer(instance.ObjectMeta.Finalizers, compv1alpha1.ScanFinalizer) {
			instance.ObjectMeta.Finalizers = append(instance.ObjectMeta.Finalizers, compv1alpha1.ScanFinalizer)
			if err := r.Client.Update(context.TODO(), instance); err != nil {
				return reconcile.Result{}, err
			}
		}
	} else {
		// The object is being deleted
		return r.scanDeleteHandler(instance, reqLogger)
	}

	// At this point, we make a copy of the instance, so we can modify it in the functions below.
	scanToBeUpdated := instance.DeepCopy()
	if cont, err := r.validate(instance, reqLogger); !cont || err != nil {
		if err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true, RequeueAfter: requeueAfterDefault}, nil
	}

	scanTypeHandler, err := getScanTypeHandler(r, scanToBeUpdated, reqLogger)
	if err != nil {
		return reconcile.Result{}, err
	}

	if cont, err := scanTypeHandler.validate(); !cont || err != nil {
		if err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true, RequeueAfter: requeueAfterDefault}, nil
	}

	switch scanToBeUpdated.Status.Phase {
	case compv1alpha1.PhasePending:
		return r.phasePendingHandler(scanToBeUpdated, reqLogger)
	case compv1alpha1.PhaseLaunching:
		return r.phaseLaunchingHandler(scanTypeHandler, reqLogger)
	case compv1alpha1.PhaseRunning:
		return r.phaseRunningHandler(scanTypeHandler, reqLogger)
	case compv1alpha1.PhaseAggregating:
		return r.phaseAggregatingHandler(scanTypeHandler, reqLogger)
	case compv1alpha1.PhaseDone:
		return r.phaseDoneHandler(scanTypeHandler, scanToBeUpdated, reqLogger, dontDelete)
	}

	// the default catch-all, just remove the request from the queue
	return reconcile.Result{}, nil
}

// validate does validation on the scan and sets some defaults. This is run before any phase to avoid
// folks modifying the scan in the middle of it and the operator not erroring out early enough.
func (r *ReconcileComplianceScan) validate(instance *compv1alpha1.ComplianceScan, logger logr.Logger) (cont bool, valerr error) {
	// If no phase set, default to pending (the initial phase):
	if instance.Status.Phase == "" {
		instanceCopy := instance.DeepCopy()
		if instance.Status.RemainingRetries != instance.Spec.MaxRetryOnTimeout {
			instanceCopy.Status.RemainingRetries = instance.Spec.MaxRetryOnTimeout
		}
		instanceCopy.Status.Phase = compv1alpha1.PhasePending
		instanceCopy.Status.StartTimestamp = nil
		instanceCopy.Status.SetConditionPending()
		updateErr := r.Client.Status().Update(context.TODO(), instanceCopy)
		if updateErr != nil {
			return false, updateErr
		}
		r.Metrics.IncComplianceScanStatus(instanceCopy.Name, instanceCopy.Status)
		return false, nil
	}

	if instance.Spec.ScanType == "" || instance.Spec.ScannerType == "" {
		instanceCopy := instance.DeepCopy()
		// Set default scan type if missing
		if instance.Spec.ScanType == "" {
			instanceCopy.Spec.ScanType = compv1alpha1.ScanTypeNode
		}
		// Set default scanner type if missing
		if instance.Spec.ScannerType == "" {
			instanceCopy.Spec.ScannerType = compv1alpha1.ScannerTypeOpenSCAP
		}
		err := r.Client.Update(context.TODO(), instanceCopy)
		return false, err
	}

	// validate scan type
	if _, err := instance.GetScanTypeIfValid(); err != nil {
		r.Recorder.Event(instance, corev1.EventTypeWarning, "InvalidScanType",
			"The scan type was invalid")
		instanceCopy := instance.DeepCopy()
		instanceCopy.Status.Result = compv1alpha1.ResultError
		instanceCopy.Status.ErrorMessage = fmt.Sprintf("Scan type '%s' is not valid", instance.Spec.ScanType)
		instanceCopy.Status.Phase = compv1alpha1.PhaseDone
		instanceCopy.Status.EndTimestamp = &metav1.Time{Time: time.Now()}
		instanceCopy.Status.SetConditionInvalid()
		updateErr := r.Client.Status().Update(context.TODO(), instanceCopy)
		if updateErr != nil {
			return false, updateErr
		}
		r.Metrics.IncComplianceScanStatus(instanceCopy.Name, instanceCopy.Status)
		return false, nil
	}

	// Set default storage if missing
	if instance.Spec.RawResultStorage.Size == "" {
		instanceCopy := instance.DeepCopy()
		instanceCopy.Spec.RawResultStorage.Size = compv1alpha1.DefaultRawStorageSize
		err := r.Client.Update(context.TODO(), instanceCopy)
		return false, err
	}

	if instance.Spec.RawResultStorage.Enabled == nil {
		instanceCopy := instance.DeepCopy()
		trueValue := true
		instanceCopy.Spec.RawResultStorage.Enabled = &trueValue
		err := r.Client.Update(context.TODO(), instanceCopy)
		return false, err
	}

	if len(instance.Spec.RawResultStorage.PVAccessModes) == 0 {
		instanceCopy := instance.DeepCopy()
		instanceCopy.Spec.RawResultStorage.PVAccessModes = defaultAccessMode
		err := r.Client.Update(context.TODO(), instanceCopy)
		return false, err
	}

	//validate raw storage size
	if _, err := resource.ParseQuantity(instance.Spec.RawResultStorage.Size); err != nil {
		instanceCopy := instance.DeepCopy()
		instanceCopy.Status.ErrorMessage = fmt.Sprintf("Error parsing RawResultsStorageSize: %s", err)
		instanceCopy.Status.Result = compv1alpha1.ResultError
		instanceCopy.Status.Phase = compv1alpha1.PhaseDone
		instanceCopy.Status.EndTimestamp = &metav1.Time{Time: time.Now()}
		instanceCopy.Status.SetConditionInvalid()
		err := r.Client.Status().Update(context.TODO(), instanceCopy)
		if err != nil {
			return false, err
		}
		r.Metrics.IncComplianceScanStatus(instanceCopy.Name, instanceCopy.Status)
		return false, nil
	}

	return true, nil
}

func (r *ReconcileComplianceScan) notifyUseOfDeprecatedProfile(instance *compv1alpha1.ComplianceScan, logger logr.Logger) error {
	profile := &compv1alpha1.Profile{}
	tp := &compv1alpha1.TailoredProfile{}
	var profileName string

	if instance.Spec.ScannerType == compv1alpha1.ScannerTypeCEL {
		tailoredProfiles := &compv1alpha1.TailoredProfileList{}
		profileGuid := instance.GetLabels()[compv1alpha1.ProfileGuidLabel]
		if err := r.Client.List(context.TODO(), tailoredProfiles, client.InNamespace(common.GetComplianceOperatorNamespace())); err != nil {
			logger.Error(err, "Could not list TailoredProfiles", "ComplianceScan", instance.Name)
			return err
		}
		for _, t := range tailoredProfiles.Items {
			if t.GetLabels()[compv1alpha1.ProfileGuidLabel] == profileGuid {
				if t.GetAnnotations()[compv1alpha1.ProfileStatusAnnotation] == "deprecated" {
					logger.Info("ComplianceScan is running with a deprecated tailored profile", "ComplianceScan", instance.Name, "TailoredProfile", t.Name)
					r.Recorder.Eventf(
						instance, corev1.EventTypeWarning, "DeprecatedTailoredProfile",
						"TailoredProfile %s is deprecated and should be avoided. "+
							"Please consider using another profile", t.Name)
				}
				return nil
			}
		}
		// For CEL scans, we don't need to check ProfileBundles
		// CEL scans use TailoredProfiles with custom rules, not ProfileBundles
		return nil
	}

	if instance.Spec.TailoringConfigMap != nil {
		// The ComplianceScan references a TailoredProfile
		tpName := xccdf.GetNameFromXCCDFTailoredProfileID(instance.Spec.Profile)

		if err := r.Client.Get(context.TODO(), types.NamespacedName{Name: tpName, Namespace: common.GetComplianceOperatorNamespace()}, tp); err != nil {
			logger.Error(err, "Could not get TailoredProfile", "TailoredProfile", tpName, "ComplianceScan", instance.Name)
			return err
		}
		if tp.GetAnnotations()[compv1alpha1.ProfileStatusAnnotation] == "deprecated" {
			logger.Info("ComplianceScan is running with a deprecated tailored profile", instance.Name, tp.Name)
			r.Recorder.Eventf(
				instance, corev1.EventTypeWarning, "DeprecatedTailoredProfile",
				"TailoredProfile %s is deprecated and should be avoided. "+
					"Please consider using another profile", tp.Name)
			return nil
		}

		if tp.Spec.Extends == "" {
			return nil
		}
		// The extends field references a profile by its full name
		profileName = tp.Spec.Extends
	} else {
		var pbName string
		pbs := &compv1alpha1.ProfileBundleList{}

		// We first find the ProfileBundle matching the scan's spec, then we get the profile that matches the scan's Profile ID.
		// We do this because a profile ID is not unique across all PBs, but is unique withing a PB.
		// We can, but should not, infer the Profile name based on the ComplianceScan name.
		// Advanced users still could create Suites and Scans with arbitrary names, and that is exactly what we do in our tests.
		if err := r.Client.List(context.TODO(), pbs, client.InNamespace(common.GetComplianceOperatorNamespace())); err != nil {
			logger.Error(err, "Could not list ProfileBundles")
			return err
		}
		for _, pb := range pbs.Items {
			if pb.Spec.ContentFile == instance.Spec.Content && pb.Spec.ContentImage == instance.Spec.ContentImage {
				pbName = pb.Name
				break
			}
		}
		if pbName == "" {
			logger.Info("Could not find ProfileBundle used by scan to check if the Profile is deprecated",
				"ComplianceScan", instance.Name,
				"Profile", instance.Spec.Profile,
				"ContentImage", instance.Spec.ContentImage,
				"Content", instance.Spec.Content)
			return nil
		}

		xccdfProfileName := xccdf.GetProfileNameFromID(instance.Spec.Profile)

		// This is the full profile name,
		// taking into account the possiblity of an 'upstream-' prefix in the PB.
		profileName = pbName + "-" + xccdfProfileName
	}

	if err := r.Client.Get(context.TODO(), types.NamespacedName{Name: profileName, Namespace: common.GetComplianceOperatorNamespace()}, profile); err != nil {
		logger.Error(err, "Could not get Profile", "profile", profileName, "ns", common.GetComplianceOperatorNamespace())
		return err
	}

	if profile.GetAnnotations()[compv1alpha1.ProfileStatusAnnotation] == "deprecated" {
		logger.Info("ComplianceScan is running with a deprecated profile", instance.Name, profile.Name)
		if instance.Spec.TailoringConfigMap != nil {
			r.Recorder.Eventf(
				instance, corev1.EventTypeWarning, "DeprecatedTailoredProfile",
				"TailoredProfile %s is extending a deprecated Profile (%s) that will be removed in a future version of Compliance Operator. "+
					"Please consider using a newer version of this profile", tp.Name, profile.Name)
		} else {
			r.Recorder.Eventf(
				instance, corev1.EventTypeWarning, "DeprecatedProfile",
				"Profile %s is deprecated and will be removed in a future version of Compliance Operator. "+
					"Please consider using a newer version of this profile", profile.Name)
		}
	}
	return nil
}

func (r *ReconcileComplianceScan) phasePendingHandler(instance *compv1alpha1.ComplianceScan, logger logr.Logger) (reconcile.Result, error) {
	logger.Info("Phase: Pending")

	err := r.notifyUseOfDeprecatedProfile(instance, logger)
	if err != nil {
		logger.Error(err, "Could not check whether the Profile used by ComplianceScan is deprecated", "ComplianceScan", instance.Name)
		instanceCopy := instance.DeepCopy()
		instanceCopy.Status.Phase = compv1alpha1.PhaseDone
		instanceCopy.Status.Result = compv1alpha1.ResultError
		instanceCopy.Status.ErrorMessage = "Could not check whether the Profile used by ComplianceScan is deprecated"
		instanceCopy.Status.StartTimestamp = &metav1.Time{Time: time.Now()}
		instanceCopy.Status.EndTimestamp = &metav1.Time{Time: time.Now()}
		err = r.Client.Status().Update(context.TODO(), instanceCopy)
		if err != nil {
			logger.Error(err, "Cannot update the status")
			return reconcile.Result{}, err
		}
		return reconcile.Result{}, nil
	}

	// Remove annotation if needed
	if instance.NeedsRescan() {
		instanceCopy := instance.DeepCopy()
		delete(instanceCopy.Annotations, compv1alpha1.ComplianceCheckCountAnnotation)
		delete(instanceCopy.Annotations, compv1alpha1.ComplianceScanRescanAnnotation)
		delete(instanceCopy.Annotations, compv1alpha1.ComplianceScanTimeoutAnnotation)
		err := r.Client.Update(context.TODO(), instanceCopy)
		return reconcile.Result{}, err
	}

	if instance.NeedsTimeoutRescan() {
		instanceCopy := instance.DeepCopy()
		delete(instanceCopy.Annotations, compv1alpha1.ComplianceScanTimeoutAnnotation)
		delete(instanceCopy.Annotations, compv1alpha1.ComplianceCheckCountAnnotation)
		err := r.Client.Update(context.TODO(), instanceCopy)
		return reconcile.Result{}, err
	}

	// Update the scan instance, the next phase is running
	instance.Status.Phase = compv1alpha1.PhaseLaunching
	instance.Status.Result = compv1alpha1.ResultNotAvailable
	instance.Status.StartTimestamp = &metav1.Time{Time: time.Now()}
	instance.Status.EndTimestamp = nil
	err = r.Client.Status().Update(context.TODO(), instance)
	if err != nil {
		logger.Error(err, "Cannot update the status")
		return reconcile.Result{}, err
	}

	// TODO: It might be better to store the list of eligible nodes in the CR so that if someone edits the CR or
	// adds/removes nodes while the scan is running, we just work on the same set?

	r.Metrics.IncComplianceScanStatus(instance.Name, instance.Status)
	return reconcile.Result{}, nil
}

func (r *ReconcileComplianceScan) phaseLaunchingHandler(h scanTypeHandler, logger logr.Logger) (reconcile.Result, error) {
	var err error

	logger.Info("Phase: Launching")

	scan := h.getScan()

	// check the scanner type of the scan
	if scan.Spec.ScannerType == compv1alpha1.ScannerTypeOpenSCAP || scan.Spec.ScannerType == "" {
		err = createConfigMaps(r, scriptCmForScan(scan), envCmForScan(scan), envCmForPlatformScan(scan), scan)
		if err != nil {
			logger.Error(err, "Cannot create the configmaps")
			return reconcile.Result{}, err
		}

		if err = r.handleRootCASecret(scan, logger); err != nil {
			logger.Error(err, "Cannot create CA secret")
			return reconcile.Result{}, err
		}

		if scan.Spec.RawResultStorage.Enabled != nil && *scan.Spec.RawResultStorage.Enabled {
			if err = r.handleResultServerSecret(scan, logger); err != nil {
				logger.Error(err, "Cannot create result server cert secret")
				return reconcile.Result{}, err
			}

			if err = r.handleResultClientSecret(scan, logger); err != nil {
				logger.Error(err, "Cannot create result Client cert secret")
				return reconcile.Result{}, err
			}

			if resume, err := r.handleRawResultsForScan(scan, logger); err != nil || !resume {
				if err != nil {
					logger.Error(err, "Cannot create the PersistentVolumeClaims")
				}
				return reconcile.Result{}, err
			}

			if err = r.createResultServer(scan, logger); err != nil {
				logger.Error(err, "Cannot create result server")
				return reconcile.Result{}, err
			}

		}

		if err = r.handleRuntimeKubeletConfig(scan, logger); err != nil {
			logger.Error(err, "Cannot handle runtime kubelet config")
			return reconcile.Result{}, err
		}
	}

	if err = h.createScanWorkload(); err != nil {
		if !common.IsRetriable(err) {
			// Surface non-retriable errors to the CR
			logger.Info("Updating scan status due to unretriable error")
			scanCopy := scan.DeepCopy()
			scanCopy.Status.ErrorMessage = err.Error()
			scanCopy.Status.Result = compv1alpha1.ResultError
			scanCopy.Status.Phase = compv1alpha1.PhaseDone
			scanCopy.Status.EndTimestamp = &metav1.Time{Time: time.Now()}
			scanCopy.Status.SetConditionInvalid()
			if updateerr := r.Client.Status().Update(context.TODO(), scanCopy); updateerr != nil {
				logger.Error(updateerr, "Failed to update a scan")
				return reconcile.Result{}, updateerr
			}
			r.Metrics.IncComplianceScanStatus(scanCopy.Name, scanCopy.Status)
		}
		return common.ReturnWithRetriableError(logger, err)
	}
	// if we got here, there are no new pods to be created, move to the next phase
	scan.Status.Phase = compv1alpha1.PhaseRunning
	scan.Status.SetConditionsProcessing()
	err = r.Client.Status().Update(context.TODO(), scan)
	if err != nil {
		// metric status update error
		return reconcile.Result{}, err
	}
	r.Metrics.IncComplianceScanStatus(scan.Name, scan.Status)
	return reconcile.Result{}, nil
}

// getRuntimeKubeletConfig gets the runtime kubeletconfig for a node
// by fetching /api/v1/nodes/$nodeName/proxy/configz endpoint use the kubeClientset
// and store it in a configmap for each node
func (r *ReconcileComplianceScan) getRuntimeKubeletConfig(nodeName string) (string, error) {
	// get the runtime kubeletconfig
	kubeletConfigIO, err := r.ClientSet.CoreV1().RESTClient().Get().RequestURI("/api/v1/nodes/" + nodeName + "/proxy/configz").Stream(context.TODO())
	if err != nil {
		return "", fmt.Errorf("cannot get the runtime kubelet config for node %s: %v", nodeName, err)
	}
	defer kubeletConfigIO.Close()
	kubeletConfig, err := ioutil.ReadAll(kubeletConfigIO)
	if err != nil {
		return "", fmt.Errorf("cannot read the runtime kubelet config for node %s: %v", nodeName, err)
	}
	// kubeletConfig is a byte array, we need to convert it to string
	kubeletConfigStr := string(kubeletConfig)
	return kubeletConfigStr, nil
}

func (r *ReconcileComplianceScan) createKubeletConfigCM(instance *compv1alpha1.ComplianceScan, node *corev1.Node) error {
	kubeletConfig, err := r.getRuntimeKubeletConfig(node.Name)
	if err != nil {
		return fmt.Errorf("cannot get the runtime kubelet config for node %s: %v", node.Name, err)
	}
	trueP := true
	// create a configmap for the node
	kubeletConfigCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getKubeletCMNameForScan(instance, node),
			Namespace: instance.Namespace,
			CreationTimestamp: metav1.Time{
				Time: time.Now(),
			},
			Labels: map[string]string{
				compv1alpha1.ComplianceScanLabel: instance.Name,
				compv1alpha1.KubeletConfigLabel:  "",
			},
		},
		Data: map[string]string{
			KubeletConfigMapName: kubeletConfig,
		},
		Immutable: &trueP,
	}
	err = r.Client.Create(context.TODO(), kubeletConfigCM)
	if err != nil {
		return err
	}
	return nil
}

func (r *ReconcileComplianceScan) getNodesForScan(instance *compv1alpha1.ComplianceScan) (corev1.NodeList, error) {
	nodes := corev1.NodeList{}
	nodeScanSelector := map[string]string{"kubernetes.io/os": "linux"}
	listOpts := client.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Merge(instance.Spec.NodeSelector, nodeScanSelector)),
	}

	if err := r.Client.List(context.TODO(), &nodes, &listOpts); err != nil {
		return nodes, err
	}
	return nodes, nil
}

func (r *ReconcileComplianceScan) handleRuntimeKubeletConfig(instance *compv1alpha1.ComplianceScan, logger logr.Logger) error {
	// only handle node scans
	if instance.Spec.ScanType != compv1alpha1.ScanTypeNode {
		return nil
	}
	nodes, err := r.getNodesForScan(instance)
	if err != nil {
		logger.Error(err, "Cannot get the nodes for the scan")
		return err
	}
	for _, node := range nodes.Items {
		// check if the configmap already exists for the node
		kubeletConfigCM := &corev1.ConfigMap{}
		err := r.Client.Get(context.TODO(), types.NamespacedName{Name: getKubeletCMNameForScan(instance, &node), Namespace: instance.Namespace}, kubeletConfigCM)
		if err != nil {
			if !errors.IsNotFound(err) {
				logger.Error(err, "Error getting the configmap for the runtime kubeletconfig", "node", node.Name)
				return err
			}
			// create a configmap for the node
			err = r.createKubeletConfigCM(instance, &node)
			logger.Info("Created a new configmap for the node", "configmap", kubeletConfigCM.Name, "node", node.Name)
			if err != nil {
				logger.Error(err, "Error creating the configmap for the runtime kubeletconfig", "node", node.Name)
				return err
			}
			continue
		}
	}
	return nil
}

func (r *ReconcileComplianceScan) phaseRunningHandler(h scanTypeHandler, logger logr.Logger) (reconcile.Result, error) {
	logger.Info("Phase: Running")

	running, timeoutNodes, err := h.handleRunningScan()

	if err != nil {
		return reconcile.Result{}, err
	}

	if len(timeoutNodes) > 0 {
		scan := h.getScan()
		scan = scan.DeepCopy()

		if scan.NeedsTimeoutRescan() {
			// If we already have rescan annotation, we need to update the scan status
			return r.updateScanStatusOnTimeout(scan, timeoutNodes, logger)
		} else {
			// If we don't have rescan annotation, we need to add them
			return r.setAnnotationOnTimeout(scan, timeoutNodes, logger)
		}
	}

	if running {
		// The platform scan pod is still running, go back to queue.
		return reconcile.Result{Requeue: true, RequeueAfter: requeueAfterDefault}, nil
	}

	scan := h.getScan()
	// if we got here, there are no pods running, move to the Aggregating phase
	scan.Status.Phase = compv1alpha1.PhaseAggregating
	err = r.Client.Status().Update(context.TODO(), scan)
	if err != nil {
		// metric status update error
		return reconcile.Result{}, err
	}
	r.Metrics.IncComplianceScanStatus(scan.Name, scan.Status)
	return reconcile.Result{}, nil
}

func (r *ReconcileComplianceScan) updateScanStatusOnTimeout(scan *compv1alpha1.ComplianceScan, timeoutNodes []string, logger logr.Logger) (reconcile.Result, error) {
	remRetries := scan.Status.RemainingRetries
	var err error
	// If we have retries left, let's retry the scan
	scan.Status.Phase = compv1alpha1.PhaseDone
	scan.Status.EndTimestamp = &metav1.Time{Time: time.Now()}
	scan.Status.Result = compv1alpha1.ResultError
	scan.Status.ErrorMessage = "Timeout while waiting for the scan pod to be finished."
	scan.Status.SetConditionTimeout()

	if remRetries > 0 {
		logger.Info("Retrying scan", "compliancescan", scan.ObjectMeta.Name, "node", strings.Join(timeoutNodes, ","))
		r.Recorder.Eventf(scan, corev1.EventTypeWarning, "Retrying", "Retrying scan %s due to timeout on %s", scan.ObjectMeta.Name, strings.Join(timeoutNodes, ","))
		scan.Status.RemainingRetries = remRetries - 1
		err = r.Client.Status().Update(context.TODO(), scan)
		if err != nil {
			return reconcile.Result{}, err
		}
	} else {
		logger.Info("No retries left, marking scan as failed", "compliancescan", scan.ObjectMeta.Name, "node", strings.Join(timeoutNodes, ","))
		scan.Status.RemainingRetries = scan.Spec.MaxRetryOnTimeout
		r.generateResultEventForScan(scan, logger)
		err = r.Client.Status().Update(context.TODO(), scan)
		if err != nil {
			return reconcile.Result{}, err
		}
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileComplianceScan) setAnnotationOnTimeout(scan *compv1alpha1.ComplianceScan, timeoutNodes []string, logger logr.Logger) (reconcile.Result, error) {
	if scan.Annotations == nil {
		scan.Annotations = make(map[string]string)
	}
	scan.Annotations[compv1alpha1.ComplianceScanTimeoutAnnotation] = strings.Join(timeoutNodes, ",")
	if scan.Status.RemainingRetries > 0 {
		scan.Annotations[compv1alpha1.ComplianceScanRescanAnnotation] = ""
	}
	err := r.Client.Update(context.TODO(), scan)
	if err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileComplianceScan) phaseAggregatingHandler(h scanTypeHandler, logger logr.Logger) (reconcile.Result, error) {
	logger.Info("Phase: Aggregating")
	instance := h.getScan()
	// We will skip aggregation if the scan is a CEL scan
	if instance.Spec.ScannerType == compv1alpha1.ScannerTypeOpenSCAP || instance.Spec.ScannerType == "" {
		isReady, warnings, err := h.shouldLaunchAggregator()

		if warnings != "" {
			instance.Status.Warnings = warnings
		}

		// We only wait if there are no errors.
		if err == nil && !isReady {
			logger.Info("ConfigMap missing (not ready). Requeuing.")
			return reconcile.Result{Requeue: true, RequeueAfter: requeueAfterDefault}, nil
		}

		if err != nil {
			instance.Status.Phase = compv1alpha1.PhaseDone
			instance.Status.EndTimestamp = &metav1.Time{Time: time.Now()}
			instance.Status.Result = compv1alpha1.ResultError
			instance.Status.SetConditionInvalid()
			instance.Status.ErrorMessage = err.Error()
			err = r.updateStatusWithEvent(instance, logger)
			if err != nil {
				// metric status update error
				return reconcile.Result{}, err
			}
			r.Metrics.IncComplianceScanStatus(instance.Name, instance.Status)
			return reconcile.Result{}, nil
		}

		logger.Info("Creating an aggregator pod for scan")
		aggregator := r.newAggregatorPod(instance, logger)
		if priorityClassExist, why := utils.ValidatePriorityClassExist(aggregator.Spec.PriorityClassName, r.Client); !priorityClassExist {
			logger.Info(why, "aggregator", aggregator.Name)
			r.Recorder.Eventf(aggregator, corev1.EventTypeWarning, "PriorityClass", why+" aggregator:"+aggregator.Name)
			aggregator.Spec.PriorityClassName = ""
		}
		err = r.launchAggregatorPod(instance, aggregator, logger)
		if err != nil {
			logger.Error(err, "Failed to launch aggregator pod", "aggregator", aggregator)
			return reconcile.Result{}, err
		}
		running, err := isAggregatorRunning(r, instance, logger)
		if errors.IsNotFound(err) {
			// Suppress loud error message by requeueing
			return reconcile.Result{Requeue: true, RequeueAfter: requeueAfterDefault / 2}, nil
		} else if err != nil {
			logger.Error(err, "Failed to check if aggregator pod is running", "aggregator", aggregator)
			return reconcile.Result{}, err
		}

		if running {
			logger.Info("Remaining in the aggregating phase")
			instance.Status.Phase = compv1alpha1.PhaseAggregating
			err = r.Client.Status().Update(context.TODO(), instance)
			if err != nil {
				logger.Error(err, "Cannot update the status, requeueing")
				return reconcile.Result{Requeue: true, RequeueAfter: requeueAfterDefault}, nil
			}
			r.Metrics.IncComplianceScanStatus(instance.Name, instance.Status)
			return reconcile.Result{Requeue: true, RequeueAfter: requeueAfterDefault}, nil
		}
	}

	logger.Info("Moving on to the Done phase")

	result, isReady, err := gatherResults(r, h)

	// We only wait if there are no errors.
	if err == nil && !isReady {
		logger.Info("ConfigMap missing or not ready. Requeuing.")
		return reconcile.Result{Requeue: true, RequeueAfter: requeueAfterDefault}, nil
	}

	instance.Status.Result = result
	if err != nil {
		instance.Status.ErrorMessage = err.Error()
	}

	// count the number of checks that were run
	checkCount, err := r.fetchResultCounts(instance, logger)
	if err != nil {
		logger.Error(err, "Cannot fetch the number of checks")
		return reconcile.Result{}, err
	}

	// check if instance has any annotation before checking for check count
	// to avoid nil pointer exception in case of missing annotation
	if instance.Annotations == nil {
		instance.Annotations = make(map[string]string)
	}
	if _, ok := instance.Annotations[compv1alpha1.ComplianceCheckCountAnnotation]; !ok {
		instanceCopy := instance.DeepCopy()
		instanceCopy.Annotations[compv1alpha1.ComplianceCheckCountAnnotation] = strconv.Itoa(checkCount)
		if err := r.Client.Update(context.TODO(), instanceCopy); err != nil {
			logger.Error(err, "Cannot update the scan with the check count")
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true}, nil
	}

	instance.Status.Phase = compv1alpha1.PhaseDone
	instance.Status.EndTimestamp = &metav1.Time{Time: time.Now()}
	instance.Status.SetConditionReady()
	err = r.updateStatusWithEvent(instance, logger)
	if err != nil {
		// metric status update error
		return reconcile.Result{}, err
	}
	r.Metrics.IncComplianceScanStatus(instance.Name, instance.Status)
	return reconcile.Result{}, nil
}

func (r *ReconcileComplianceScan) fetchResultCounts(scan *compv1alpha1.ComplianceScan, logger logr.Logger) (int, error) {
	var checkList compv1alpha1.ComplianceCheckResultList
	checkListOpts := client.MatchingLabels{
		compv1alpha1.ComplianceScanLabel: scan.Name,
	}
	if err := r.Client.List(context.TODO(), &checkList, &checkListOpts); err != nil {
		logger.Error(err, "Cannot list the check results")
		return 0, err
	}
	return len(checkList.Items), nil
}

func (r *ReconcileComplianceScan) phaseDoneHandler(h scanTypeHandler, instance *compv1alpha1.ComplianceScan, logger logr.Logger, doDelete bool) (reconcile.Result, error) {
	var err error
	logger.Info("Phase: Done")

	// the scan pods and the aggregator are done at this point and can be cleaned up
	// unless we are running in debug mode and thus requested them to stay
	// around for later inspection
	if doDelete == true || instance.Spec.Debug == false || instance.NeedsRescan() {
		// Don't try to clean up scan-type specific resources
		// if it was an unknown scan type
		if h != nil {
			if err := h.cleanup(); err != nil {
				logger.Error(err, "Cannot clean up scan pods")
				return reconcile.Result{}, err
			}
		}

		if err := r.deleteAggregator(instance, logger); err != nil {
			logger.Error(err, "Cannot delete aggregator")
			return reconcile.Result{}, err
		}

	}

	// We need to remove resources before doing a re-scan
	if doDelete || instance.NeedsRescan() {
		logger.Info("Cleaning up scan's resources")
		if instance.Spec.ScannerType == compv1alpha1.ScannerTypeOpenSCAP || instance.Spec.ScannerType == "" {

			if err := r.deleteResultServer(instance, logger); err != nil {
				logger.Error(err, "Cannot delete result server")
				return reconcile.Result{}, err
			}

			if err = r.deleteResultServerSecret(instance, logger); err != nil {
				logger.Error(err, "Cannot delete result server cert secret")
				return reconcile.Result{}, err
			}

			if err = r.deleteResultClientSecret(instance, logger); err != nil {
				logger.Error(err, "Cannot delete result Client cert secret")
				return reconcile.Result{}, err
			}

			if err = r.deleteRootCASecret(instance, logger); err != nil {
				logger.Error(err, "Cannot delete CA secret")
				return reconcile.Result{}, err
			}

			if err = r.deleteScriptConfigMaps(instance, logger); err != nil {
				logger.Error(err, "Cannot delete script ConfigMaps")
				return reconcile.Result{}, err
			}

			if err := r.deleteKubeletConfigConfigMaps(instance, logger); err != nil {
				logger.Error(err, "Cannot delete KubeletConfig ConfigMaps")
				return reconcile.Result{}, err
			}
		}

		if instance.NeedsRescan() {

			if err = r.deleteResultConfigMaps(instance, logger); err != nil {
				logger.Error(err, "Cannot delete result ConfigMaps")
				return reconcile.Result{}, err
			}

			// reset phase
			logger.Info("Resetting scan")
			instanceCopy := instance.DeepCopy()
			instanceCopy.Status.Phase = compv1alpha1.PhasePending
			instanceCopy.Status.Result = compv1alpha1.ResultNotAvailable
			instanceCopy.Status.StartTimestamp = nil
			if instance.Status.CurrentIndex == math.MaxInt64 {
				instanceCopy.Status.CurrentIndex = 0
			} else {
				instanceCopy.Status.CurrentIndex = instance.Status.CurrentIndex + 1
			}
			err = r.Client.Status().Update(context.TODO(), instanceCopy)
			if err != nil {
				// metric status update error
				return reconcile.Result{}, err
			}
			r.Metrics.IncComplianceScanStatus(instanceCopy.Name, instanceCopy.Status)
			return reconcile.Result{}, nil
		}
	} else {
		// If we're done with the scan but we're not cleaning up just yet.
		if (instance.Spec.RawResultStorage.Enabled != nil && *instance.Spec.RawResultStorage.Enabled) || (instance.Spec.ScannerType == compv1alpha1.ScannerTypeOpenSCAP || instance.Spec.ScannerType == "") {

			// scale down resultserver so it's not still listening for requests.
			if err := r.scaleDownResultServer(instance, logger); err != nil {
				logger.Error(err, "Cannot scale down result server")
				return reconcile.Result{}, err
			}

		}
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileComplianceScan) scanDeleteHandler(instance *compv1alpha1.ComplianceScan, logger logr.Logger) (reconcile.Result, error) {
	if common.ContainsFinalizer(instance.ObjectMeta.Finalizers, compv1alpha1.ScanFinalizer) {
		logger.Info("The scan is being deleted")
		scanToBeDeleted := instance.DeepCopy()

		scanTypeHandler, err := getScanTypeHandler(r, scanToBeDeleted, logger)
		if err != nil && !goerrors.Is(err, compv1alpha1.ErrUnkownScanType) {
			return reconcile.Result{}, err
		}

		// Force remove rescan annotation since we're deleting the scan
		if scanToBeDeleted.NeedsRescan() {
			delete(scanToBeDeleted.Annotations, compv1alpha1.ComplianceScanRescanAnnotation)
		}

		// remove objects by forcing handling of phase DONE
		if _, err := r.phaseDoneHandler(scanTypeHandler, scanToBeDeleted, logger, doDelete); err != nil {
			// if fail to delete the external dependency here, return with error
			// so that it can be retried
			return reconcile.Result{}, err
		}

		if err := r.deleteResultConfigMaps(scanToBeDeleted, logger); err != nil {
			logger.Error(err, "Cannot delete result ConfigMaps")
			return reconcile.Result{}, err
		}

		if err := r.deleteRawResultsForScan(scanToBeDeleted); err != nil {
			logger.Error(err, "Cannot delete raw results")
			return reconcile.Result{}, err
		}

		// remove our finalizer from the list and update it.
		scanToBeDeleted.ObjectMeta.Finalizers = common.RemoveFinalizer(scanToBeDeleted.ObjectMeta.Finalizers, compv1alpha1.ScanFinalizer)
		if err := r.Client.Update(context.TODO(), scanToBeDeleted); err != nil {
			return reconcile.Result{}, err
		}
	}

	// Stop reconciliation as the item is being deleted
	return reconcile.Result{}, nil
}

func (r *ReconcileComplianceScan) updateStatusWithEvent(scan *compv1alpha1.ComplianceScan, logger logr.Logger) error {
	err := r.Client.Status().Update(context.TODO(), scan)
	if err != nil {
		return err
	}
	if r.Recorder != nil {
		r.generateResultEventForScan(scan, logger)
	}
	return nil
}

func (r *ReconcileComplianceScan) generateResultEventForScan(scan *compv1alpha1.ComplianceScan, logger logr.Logger) {
	logger.Info("Generating result event for scan")

	// Event for Suite
	r.Recorder.Eventf(
		scan, corev1.EventTypeNormal, "ResultAvailable",
		"ComplianceScan's result is: %s", scan.Status.Result,
	)

	if scan.Status.Result == compv1alpha1.ResultNotApplicable {
		r.Recorder.Eventf(
			scan, corev1.EventTypeWarning, "ScanNotApplicable",
			"The scan result is not applicable, please check if you're using the correct platform or if the nodeSelector matches nodes.")
	} else if scan.Status.Result == compv1alpha1.ResultInconsistent {
		r.Recorder.Eventf(
			scan, corev1.EventTypeNormal, "ScanNotConsistent",
			"The scan result is not consistent, please check for scan results labeled with %s",
			compv1alpha1.ComplianceCheckInconsistentLabel)
	}

	err, haveOutdatedRems := utils.HaveOutdatedRemediations(r.Client)
	if err != nil {
		logger.Info("Could not check if there exist any obsolete remediations", "Scan.Name", scan.Name)
	}
	if haveOutdatedRems {
		r.Recorder.Eventf(
			scan, corev1.EventTypeNormal, "HaveOutdatedRemediations",
			"The scan produced outdated remediations, please check for complianceremediation objects labeled with %s",
			compv1alpha1.OutdatedRemediationLabel)
	}
}

func (r *ReconcileComplianceScan) deleteScriptConfigMaps(instance *compv1alpha1.ComplianceScan, logger logr.Logger) error {
	inNs := client.InNamespace(common.GetComplianceOperatorNamespace())
	withLabel := client.MatchingLabels{
		compv1alpha1.ComplianceScanLabel: instance.Name,
		compv1alpha1.ScriptLabel:         "",
	}
	err := r.Client.DeleteAllOf(context.Background(), &corev1.ConfigMap{}, inNs, withLabel)
	if err != nil {
		return err
	}
	return nil
}

func (r *ReconcileComplianceScan) deleteResultConfigMaps(instance *compv1alpha1.ComplianceScan, logger logr.Logger) error {
	inNs := client.InNamespace(common.GetComplianceOperatorNamespace())
	withLabel := client.MatchingLabels{compv1alpha1.ComplianceScanLabel: instance.Name}
	err := r.Client.DeleteAllOf(context.Background(), &corev1.ConfigMap{}, inNs, withLabel)
	if err != nil {
		return err
	}
	return nil
}

func (r *ReconcileComplianceScan) deleteKubeletConfigConfigMaps(instance *compv1alpha1.ComplianceScan, logger logr.Logger) error {
	inNs := client.InNamespace(common.GetComplianceOperatorNamespace())
	withLabel := client.MatchingLabels{
		compv1alpha1.ComplianceScanLabel: instance.Name,
		compv1alpha1.KubeletConfigLabel:  "",
	}
	err := r.Client.DeleteAllOf(context.Background(), &corev1.ConfigMap{}, inNs, withLabel)
	if err != nil {
		return err
	}
	return nil
}

// returns true if the pod is still running, false otherwise
func isPodRunningInNode(r *ReconcileComplianceScan, scanInstance *compv1alpha1.ComplianceScan, node *corev1.Node, timeout time.Duration, logger logr.Logger) (bool, error) {
	podName := getPodForNodeName(scanInstance.Name, node.Name)
	return isPodRunning(r, podName, common.GetComplianceOperatorNamespace(), timeout, logger)
}

// returns true if the pod is still running, false otherwise
func isPlatformScanPodRunning(r *ReconcileComplianceScan, scanInstance *compv1alpha1.ComplianceScan, timeout time.Duration, logger logr.Logger) (bool, error) {
	logger.Info("Retrieving platform scan pod.", "Name", scanInstance.Name+"-"+PlatformScanName)

	podName := getPodForNodeName(scanInstance.Name, PlatformScanName)
	return isPodRunning(r, podName, common.GetComplianceOperatorNamespace(), timeout, logger)
}

func isPodRunning(r *ReconcileComplianceScan, podName, namespace string, timeout time.Duration, logger logr.Logger) (bool, error) {
	podlogger := logger.WithValues("Pod.Name", podName)
	foundPod := &corev1.Pod{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: podName, Namespace: namespace}, foundPod)
	if err != nil {
		podlogger.Error(err, "Cannot retrieve pod")
		return false, err
	} else if foundPod.Status.Phase == corev1.PodSucceeded {
		podlogger.Info("Pod has finished")
		return false, nil
	}

	// Check PodScheduled condition
	for _, condition := range foundPod.Status.Conditions {
		if condition.Type == corev1.PodScheduled {
			if condition.Reason == corev1.PodReasonUnschedulable {
				podlogger.Info("Pod unschedulable")
				return false, newPodUnschedulableError(foundPod.Name, condition.Message)
			}
			break
		}
	}

	// We check for failured in the end, as we want to make sure that conditions
	// are checked first.
	if foundPod.Status.Phase == corev1.PodFailed {
		podlogger.Info("Pod failed. It should be restarted.", "Reason", foundPod.Status.Reason, "Message", foundPod.Status.Message)
		// We mark this as if the pod is still running, as it should be
		// restarted by the kubelet due to the restart policy
		return true, nil
	}

	// the pod is still running or being created etc
	podlogger.Info("Pod still running")

	// if timeout is not set, we don't check for timeout
	if timeout == podTimeoutDisable {
		return true, nil
	}

	podCreatiopnTime := foundPod.CreationTimestamp.Time
	if time.Since(podCreatiopnTime) > timeout {
		podlogger.Info("Pod timed out")
		timeoutErr := common.NewTimeoutError("Timeout reached while waiting for the scan to finish in the pod: %s", podName)
		return true, timeoutErr
	}

	return true, nil
}

func getPlatformScanCM(r *ReconcileComplianceScan, instance *compv1alpha1.ComplianceScan) (*corev1.ConfigMap, error) {
	targetCM := types.NamespacedName{
		Name:      getConfigMapForNodeName(instance.Name, PlatformScanName),
		Namespace: common.GetComplianceOperatorNamespace(),
	}

	foundCM := &corev1.ConfigMap{}
	err := r.Client.Get(context.TODO(), targetCM, foundCM)
	return foundCM, err
}

func getNodeScanCM(r *ReconcileComplianceScan, instance *compv1alpha1.ComplianceScan, nodeName string) (*corev1.ConfigMap, error) {
	targetCM := types.NamespacedName{
		Name:      getConfigMapForNodeName(instance.Name, nodeName),
		Namespace: common.GetComplianceOperatorNamespace(),
	}

	foundCM := &corev1.ConfigMap{}
	err := r.Client.Get(context.TODO(), targetCM, foundCM)
	return foundCM, err
}

// gatherResults will iterate the nodes in the scan and get the results
// for the OpenSCAP check. If the results haven't yet been persisted in
// the relevant ConfigMap, the a requeue will be requested since the
// results are not ready.
func gatherResults(r *ReconcileComplianceScan, h scanTypeHandler) (compv1alpha1.ComplianceScanStatusResult, bool, error) {
	instance := h.getScan()

	result, isReady, err := h.gatherResults()

	if err != nil {
		return result, isReady, err
	}

	// If there are any inconsistent results, always just return
	// the state as inconsistent unless there was an error earlier
	var checkList compv1alpha1.ComplianceCheckResultList
	checkListOpts := client.MatchingLabels{
		compv1alpha1.ComplianceCheckInconsistentLabel: "",
		compv1alpha1.ComplianceScanLabel:              instance.Name,
	}
	if err := r.Client.List(context.TODO(), &checkList, &checkListOpts); err != nil {
		isReady = false
	}
	if len(checkList.Items) > 0 {
		return compv1alpha1.ResultInconsistent, isReady,
			fmt.Errorf("results were not consistent, search for compliancecheckresults labeled with %s",
				compv1alpha1.ComplianceCheckInconsistentLabel)
	}

	return result, isReady, nil
}

// pod names are limited to 63 chars, inclusive. Try to use a friendly name, if that can't be done,
// just use a hash. Either way, the node would be present in a label of the pod.
func getPodForNodeName(scanName, nodeName string) string {
	return utils.DNSLengthName("openscap-pod-", "%s-%s-pod", scanName, nodeName)
}

func getConfigMapForNodeName(scanName, nodeName string) string {
	return utils.DNSLengthName("openscap-pod-", "%s-%s-pod", scanName, nodeName)
}

func getInitContainerImage(scanSpec *compv1alpha1.ComplianceScanSpec, logger logr.Logger) string {
	image := utils.GetComponentImage(utils.CONTENT)

	if scanSpec.ContentImage != "" {
		image = scanSpec.ContentImage
	}

	logger.Info("Content image", "image", image)
	return image
}
