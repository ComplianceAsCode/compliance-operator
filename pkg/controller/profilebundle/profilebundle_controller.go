package profilebundle

import (
	"context"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/metrics"

	// #nosec G505

	"fmt"
	"path"

	compliancev1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/common"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
	"github.com/go-logr/logr"
	ocpimg "github.com/openshift/api/image/v1"
	"github.com/openshift/library-go/pkg/image/reference"
	ocptrigger "github.com/openshift/library-go/pkg/image/trigger"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var log = logf.Log.WithName("profilebundlectrl")

var oneReplica int32 = 1

func (r *ReconcileProfileBundle) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&compliancev1alpha1.ProfileBundle{}).
		Complete(r)
}

// Add creates a new ProfileBundle Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, met *metrics.Metrics, si utils.CtlplaneSchedulingInfo, _ *kubernetes.Clientset) error {
	return add(mgr, newReconciler(mgr, met, si))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, met *metrics.Metrics, si utils.CtlplaneSchedulingInfo) reconcile.Reconciler {
	return &ReconcileProfileBundle{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		reader:         mgr.GetAPIReader(),
		Metrics:        met,
		schedulingInfo: si,
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("profilebundle-controller").
		For(&compliancev1alpha1.ProfileBundle{}).
		Complete(r)
}

// blank assignment to verify that ReconcileProfileBundle implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileProfileBundle{}

// ReconcileProfileBundle reconciles a ProfileBundle object
type ReconcileProfileBundle struct {
	// Accesses the API server directly
	reader client.Reader
	// This Client, initialized using mgr.Client() above, is a split Client
	// that reads objects from the cache and writes to the apiserver
	Client  client.Client
	Scheme  *runtime.Scheme
	Metrics *metrics.Metrics
	// helps us schedule platform scans on the nodes labeled for the
	// compliance operator's control plane
	schedulingInfo utils.CtlplaneSchedulingInfo
}

// Reconcile reads that state of the cluster for a ProfileBundle object and makes changes based on the state read
// and what is in the ProfileBundle.Spec
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileProfileBundle) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling ProfileBundle")

	// Fetch the ProfileBundle instance
	instance := &compliancev1alpha1.ProfileBundle{}
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
		if !common.ContainsFinalizer(instance.ObjectMeta.Finalizers, compliancev1alpha1.ProfileBundleFinalizer) {
			pb := instance.DeepCopy()
			pb.ObjectMeta.Finalizers = append(pb.ObjectMeta.Finalizers, compliancev1alpha1.ProfileBundleFinalizer)
			if err := r.Client.Update(context.TODO(), pb); err != nil {
				return reconcile.Result{}, err
			}
			return reconcile.Result{}, nil
		}
	} else {
		// The object is being deleted
		return reconcile.Result{}, r.profileBundleDeleteHandler(instance, reqLogger)
	}

	// We should always start with an appropriate status
	if instance.Status.DataStreamStatus == "" {
		pb := instance.DeepCopy()
		pb.Status.DataStreamStatus = compliancev1alpha1.DataStreamPending
		pb.Status.SetConditionPending()
		err = r.Client.Status().Update(context.TODO(), pb)
		if err != nil {
			reqLogger.Error(err, "Couldn't update ProfileBundle status")
			return reconcile.Result{}, err
		}
		// this was a fatal error, don't requeue
		return reconcile.Result{}, nil
	}

	err = r.deleteNonNamespacedWorkload(instance, reqLogger)
	if err != nil {
		return reconcile.Result{}, err
	}

	annotations := map[string]string{}
	isISTag, isTagImageRef, err := r.pointsToISTag(instance.Spec.ContentImage)
	if err != nil {
		if common.IsRetriable(err) {
			return reconcile.Result{}, err
		}

		pbCopy := instance.DeepCopy()
		pbCopy.Status.DataStreamStatus = compliancev1alpha1.DataStreamInvalid
		pbCopy.Status.ErrorMessage = err.Error()
		pbCopy.Status.SetConditionInvalid()
		err = r.Client.Status().Update(context.TODO(), pbCopy)
		if err != nil {
			reqLogger.Error(err, "Couldn't update ProfileBundle status")
			return reconcile.Result{}, err
		}
		// this was a fatal error, don't requeue
		return reconcile.Result{}, nil
	}

	effectiveImage := instance.Spec.ContentImage
	if isISTag {
		// NOTE(jaosorior): Errors were already checked for in the pointsToISTag function
		ref, _ := reference.Parse(instance.Spec.ContentImage)
		annotations = getISTagAnnotation(ref.NameString(), getISTagNamespace(ref))
		effectiveImage = isTagImageRef
	}

	// Define a new Pod object
	depl := r.newWorkloadForBundle(instance, effectiveImage)

	found := &appsv1.Deployment{}
	err = r.Client.Get(context.TODO(), types.NamespacedName{Name: depl.Name, Namespace: depl.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new Workload", "Deployment.Namespace", depl.Namespace, "Deployment.Name", depl.Name)
		depl.Annotations = annotations
		err = r.Client.Create(context.TODO(), depl)
		if err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{Requeue: true, RequeueAfter: 10 * time.Second}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	if workloadNeedsUpdate(effectiveImage, found) {
		pbCopy := instance.DeepCopy()
		pbCopy.Status.DataStreamStatus = compliancev1alpha1.DataStreamPending
		pbCopy.Status.ErrorMessage = ""
		pbCopy.Status.SetConditionPending()
		err = r.Client.Status().Update(context.TODO(), pbCopy)
		if err != nil {
			reqLogger.Error(err, "Couldn't update ProfileBundle status")
			return reconcile.Result{}, err
		}

		// This should have a copy of
		updatedDepl := found.DeepCopy()
		updatedDepl.Spec.Template = depl.Spec.Template
		// Copy annotations if needed
		for key, val := range annotations {
			updatedDepl.Annotations[key] = val
		}
		reqLogger.Info("Updating Workload", "Deployment.Namespace", depl.Namespace, "Deployment.Name", depl.Name)
		err = r.Client.Update(context.TODO(), updatedDepl)
		if err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{Requeue: true, RequeueAfter: 10 * time.Second}, nil
	}

	labels := getWorkloadLabels(instance)
	foundPods := &corev1.PodList{}
	err = r.Client.List(context.TODO(), foundPods, client.MatchingLabels(labels))

	if len(foundPods.Items) == 0 {
		reqLogger.Info("Pod not scheduled yet. Waiting for Deployment to do it.",
			"Deployment.Namespace", depl.Namespace, "Deployment.Name", depl.Name)
		return reconcile.Result{Requeue: true, RequeueAfter: 10 * time.Second}, nil
	}

	// If there was a transcient error such as the image not being
	// fetched (Image pull error) the Deployment will schedule a new
	// pod. So let's find the newest.
	relevantPod := utils.FindNewestPod(foundPods.Items)

	if podStartupError(relevantPod) {
		// report to status
		pbCopy := instance.DeepCopy()
		pbCopy.Status.DataStreamStatus = compliancev1alpha1.DataStreamInvalid
		pbCopy.Status.ErrorMessage = "The init container failed to start. Verify Status.ContentImage."
		pbCopy.Status.SetConditionInvalid()
		err = r.Client.Status().Update(context.TODO(), pbCopy)
		if err != nil {
			reqLogger.Error(err, "Couldn't update ProfileBundle status")
			return reconcile.Result{}, err
		}
		// this was a fatal error, don't requeue
		return reconcile.Result{}, nil
	}

	// Pod already exists and its init container at least ran - don't requeue
	reqLogger.Info("Skip reconcile: Workload already up-to-date", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)

	// Handle upgrades
	if instance.Status.DataStreamStatus == compliancev1alpha1.DataStreamValid &&
		instance.Status.Conditions.GetCondition("Ready") == nil {
		reqLogger.Info("Updating Profile Bundle condition to valid")
		pbCopy := instance.DeepCopy()
		pbCopy.Status.SetConditionReady()
		err = r.Client.Status().Update(context.TODO(), pbCopy)
		if err != nil {
			reqLogger.Error(err, "Couldn't update ProfileBundle status")
			return reconcile.Result{}, err
		}
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileProfileBundle) profileBundleDeleteHandler(pb *compliancev1alpha1.ProfileBundle, logger logr.Logger) error {
	logger.Info("The ProfileBundle is being deleted")
	pod := r.newWorkloadForBundle(pb, "")
	logger.Info("Deleting profileparser workload", "Pod.Name", pod.Name)
	err := r.Client.Delete(context.TODO(), pod)
	if err != nil && !errors.IsNotFound(err) {
		return err
	}

	pbCopy := pb.DeepCopy()
	// remove our finalizer from the list and update it.
	pbCopy.ObjectMeta.Finalizers = common.RemoveFinalizer(pbCopy.ObjectMeta.Finalizers, compliancev1alpha1.ProfileBundleFinalizer)
	if err := r.Client.Update(context.TODO(), pbCopy); err != nil {
		return err
	}
	return nil
}

func (r *ReconcileProfileBundle) pointsToISTag(contentImageRef string) (bool, string, error) {
	ref, err := reference.Parse(contentImageRef)
	if err != nil {
		return false, "", common.NewNonRetriableCtrlError("the 'contentImage' does not appear to be a valid reference to an image: %v", err)
	}
	if len(ref.Registry) > 0 || len(ref.ID) > 0 {
		return false, "", nil
	}
	if len(ref.Tag) == 0 {
		return false, "", common.NewNonRetriableCtrlError("the 'contentImage' must include the tag you wish to pull from")
	}
	imageName := ref.NameString()
	imageNamespace := getISTagNamespace(ref)

	istag := &ocpimg.ImageStreamTag{}
	key := types.NamespacedName{
		Name:      imageName,
		Namespace: imageNamespace,
	}

	// We need to use the API reader here because openshift-apiserver doesn't allow
	// watching for ImageStreamTag resources. Hence, we don't want this to end up
	// with the informer failing to watch the resource.
	if err := r.reader.Get(context.TODO(), key, istag); err != nil {
		if errors.IsNotFound(err) || runtime.IsNotRegisteredError(err) || meta.IsNoMatchError(err) {
			return false, "", nil
		}
		// If you're not allowed access to the image stream, just let the container fail
		// the error will manifest itself as "ImagePullBackOff".
		if errors.IsForbidden(err) {
			return false, "", nil
		}
		return false, "", err
	}
	return true, istag.Image.DockerImageReference, nil

}

// This is temporary code that handles updates from version
// that didn't include https://github.com/ComplianceAsCode/compliance-operator/pull/467
func (r *ReconcileProfileBundle) deleteNonNamespacedWorkload(pb *compliancev1alpha1.ProfileBundle, logger logr.Logger) error {
	oldDeployName := types.NamespacedName{
		Name:      pb.Name + "-pp",
		Namespace: common.GetComplianceOperatorNamespace(),
	}
	nonNamespacedFound := &appsv1.Deployment{}
	err := r.Client.Get(context.TODO(), oldDeployName, nonNamespacedFound)
	if errors.IsNotFound(err) {
		// no such old deployment exists
		return nil
	}
	if err != nil {
		logger.Error(err, "Couldn't retrieve old deployment", "oldDeployNamespacedName", oldDeployName)
		return err
	}

	if !hasWorkloadLabels(nonNamespacedFound, pb) {
		logger.Info("Not deleting deployment that doesn't have the expected labels", "oldDeployNamespacedName", oldDeployName)
		return nil
	}

	logger.Info("Deleting old deployment", "oldDeployNamespacedName", oldDeployName)
	err = r.Client.Delete(context.TODO(), nonNamespacedFound)
	if errors.IsNotFound(err) {
		err = nil
	}

	if err != nil {
		logger.Error(err, "Couldn't delete old deployment", "oldDeployNamespacedName", oldDeployName)
		return err
	}

	// now the error can only be IsNotFound -> no old deploy exists
	return nil
}

// Gets the namespace for the image stream tag. If none is given, it'll use the operator's namespace
func getISTagNamespace(ref reference.DockerImageReference) string {
	if ref.Namespace != "" {
		return ref.Namespace
	}
	return common.GetComplianceOperatorNamespace()
}

func getWorkloadLabels(pb *compliancev1alpha1.ProfileBundle) map[string]string {
	return map[string]string{
		"profile-bundle": pb.Name,
		"workload":       "profileparser",
	}
}

func hasWorkloadLabels(obj metav1.Object, pb *compliancev1alpha1.ProfileBundle) bool {
	labels := obj.GetLabels()
	if labels == nil {
		return false
	}

	if labels["profile-bundle"] == pb.Name && labels["workload"] == "profileparser" {
		return true
	}

	return false
}

// This annotation
func getISTagAnnotation(isTagName, isTagNamespace string) map[string]string {
	annotationFmt := `[{"from":{"kind":"ImageStreamTag","name":"%s","namespace":"%s"},"fieldPath":"spec.template.spec.initContainers[?(@.name==\"content-container\")].image"}]`
	triggerAnn := fmt.Sprintf(annotationFmt, isTagName, isTagNamespace)
	return map[string]string{
		ocptrigger.TriggerAnnotationKey: triggerAnn,
	}
}

func (r *ReconcileProfileBundle) newWorkloadForBundle(pb *compliancev1alpha1.ProfileBundle, image string) *appsv1.Deployment {
	falseP := false
	trueP := true
	labels := getWorkloadLabels(pb)
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pb.Name + "-" + pb.Namespace + "-pp",
			Namespace: common.GetComplianceOperatorNamespace(),
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &oneReplica,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
					Annotations: map[string]string{
						"workload.openshift.io/management": `{"effect": "PreferredDuringScheduling"}`,
					},
				},
				Spec: corev1.PodSpec{
					NodeSelector: r.schedulingInfo.Selector,
					Tolerations:  r.schedulingInfo.Tolerations,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: &trueP,
					},
					InitContainers: []corev1.Container{
						{
							Name:  "content-container",
							Image: image,
							Command: []string{
								"sh",
								"-c",
								fmt.Sprintf("cp %s /content | /bin/true", path.Join("/", pb.Spec.ContentFile)),
							},
							ImagePullPolicy: corev1.PullAlways,
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: &falseP,
								ReadOnlyRootFilesystem:   &trueP,
								RunAsNonRoot:             &trueP,
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse("10Mi"),
									corev1.ResourceCPU:    resource.MustParse("10m"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse("50Mi"),
									corev1.ResourceCPU:    resource.MustParse("50m"),
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "content-dir",
									MountPath: "/content",
								},
							},
						},
						{
							Name:  "profileparser",
							Image: utils.GetComponentImage(utils.OPERATOR),
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: &falseP,
								ReadOnlyRootFilesystem:   &trueP,
								RunAsNonRoot:             &trueP,
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse("20Mi"),
									corev1.ResourceCPU:    resource.MustParse("10m"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse("200Mi"),
									corev1.ResourceCPU:    resource.MustParse("100m"),
								},
							},
							Command: []string{
								"compliance-operator", "profileparser",
								"--name", pb.Name,
								"--namespace", pb.Namespace,
								"--ds-path", path.Join("/content", pb.Spec.ContentFile),
							},
							Env: []corev1.EnvVar{
								corev1.EnvVar{Name: "PLATFORM", Value: utils.GetPlatform()},
								corev1.EnvVar{Name: "CONTROL_PLANE_TOPOLOGY", Value: utils.GetControlPlaneTopology()},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "content-dir",
									MountPath: "/content",
									ReadOnly:  true,
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:  "pauser",
							Image: utils.GetComponentImage(utils.OPERATOR),
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: &falseP,
								ReadOnlyRootFilesystem:   &trueP,
								RunAsNonRoot:             &trueP,
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
							},
							Command: []string{
								"/bin/sh", "-c",
							},
							Args: []string{`
							sleep infinity & PID=$!
							trap "kill $PID" INT TERM

							echo This is merely a pause container. You should instead check the logs of profileparser
							# Waits for the sleep infinity running in the background and always returns zero
							wait
							`},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse("1Mi"),
									corev1.ResourceCPU:    resource.MustParse("10m"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse("30Mi"),
									corev1.ResourceCPU:    resource.MustParse("10m"),
								},
							},
						},
					},
					ServiceAccountName: "profileparser",
					Volumes: []corev1.Volume{
						{
							Name: "content-dir",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
					},
				},
			},
		},
	}
}

// podStartupError returns false if for some reason the pod couldn't even
// run. If there's more conditions in the function in the future, let's
// split it
func podStartupError(pod *corev1.Pod) bool {
	// Check if the init container couldn't even run because the content image
	// was wrong
	for _, initStatus := range pod.Status.InitContainerStatuses {
		if initStatus.Ready == true {
			// in case there was a transient error before we reconciled,
			// just shortcut the loop and return false
			break
		}

		if initStatus.State.Waiting == nil {
			continue
		}

		switch initStatus.State.Waiting.Reason {
		case "ImagePullBackOff", "ErrImagePull":
			return true
		}
	}

	return false
}

func workloadNeedsUpdate(image string, depl *appsv1.Deployment) bool {
	initContainers := depl.Spec.Template.Spec.InitContainers
	if len(initContainers) != 2 {
		// For some weird reason we don't have the amount of init containers we expect.
		return true
	}

	isSameContentImage := false
	isSaneProfileparserImage := false

	for _, container := range initContainers {
		if container.Name == "content-container" {
			// we need an update if the image reference doesn't match.
			isSameContentImage = container.Image == image
		}
		if container.Name == "profileparser" {
			isSaneProfileparserImage = utils.GetComponentImage(utils.OPERATOR) == container.Image
		}
	}

	return !(isSameContentImage && isSaneProfileparserImage)
}
