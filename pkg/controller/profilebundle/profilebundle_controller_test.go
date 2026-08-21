package profilebundle

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	compliancev1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
)

// TestNewWorkloadForBundleUsesRecreateStrategy guards against the profileparser
// Deployment reverting to the default RollingUpdate strategy. The profileparser
// init container writes the ProfileBundle status; under RollingUpdate the old
// pod (e.g. still crash-looping on a bad content image) keeps running alongside
// the new pod that parses the fixed image, so the two race to set the status
// and can leave the ProfileBundle stuck non-VALID. Recreate guarantees a single
// parser pod at a time.
func TestNewWorkloadForBundleUsesRecreateStrategy(t *testing.T) {
	r := &ReconcileProfileBundle{}
	pb := &compliancev1alpha1.ProfileBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pb",
			Namespace: "openshift-compliance",
		},
		Spec: compliancev1alpha1.ProfileBundleSpec{
			ContentImage: "example.com/content:from",
			ContentFile:  "ssg-ocp4-ds.xml",
		},
	}

	depl := r.newWorkloadForBundle(pb, pb.Spec.ContentImage)

	if got := depl.Spec.Strategy.Type; got != appsv1.RecreateDeploymentStrategyType {
		t.Errorf("expected profileparser Deployment to use %q strategy, got %q",
			appsv1.RecreateDeploymentStrategyType, got)
	}
}

// TestProfileParserPodTemplateCarriesNetworkPolicyMarker verifies the
// profileparser pod template carries the operand NetworkPolicy marker, and that
// the marker does not leak into the immutable Deployment selector.
func TestProfileParserPodTemplateCarriesNetworkPolicyMarker(t *testing.T) {
	r := &ReconcileProfileBundle{}
	pb := &compliancev1alpha1.ProfileBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pb",
			Namespace: "openshift-compliance",
		},
		Spec: compliancev1alpha1.ProfileBundleSpec{
			ContentImage: "example.com/content:v1",
			ContentFile:  "ssg-ocp4-ds.xml",
		},
	}
	depl := r.newWorkloadForBundle(pb, "example.com/content:v1")

	if v, ok := depl.Spec.Template.ObjectMeta.Labels[compliancev1alpha1.NetworkPolicyOperandLabel]; !ok || v != "" {
		t.Errorf("profileparser pod template missing NetworkPolicy marker (labels=%v)",
			depl.Spec.Template.ObjectMeta.Labels)
	}
	if _, ok := depl.Spec.Selector.MatchLabels[compliancev1alpha1.NetworkPolicyOperandLabel]; ok {
		t.Error("profileparser Deployment selector must not carry the NetworkPolicy marker")
	}
}

func TestWorkloadNeedsUpdateDetectsCELContentFileChange(t *testing.T) {
	image := "example.com/content:v1"
	operatorImage := utils.GetComponentImage(utils.OPERATOR)

	pbNoCEL := &compliancev1alpha1.ProfileBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ocp4",
			Namespace: "openshift-compliance",
		},
		Spec: compliancev1alpha1.ProfileBundleSpec{
			ContentImage: image,
			ContentFile:  "ssg-ocp4-ds.xml",
		},
	}
	pbWithCEL := pbNoCEL.DeepCopy()
	pbWithCEL.Spec.CELContentFile = "ocp4-cel-content.yaml"

	deplFromNoCEL := &appsv1.Deployment{
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:    "content-container",
							Image:   image,
							Command: []string{"sh", "-c", contentCopyCommand(pbNoCEL)},
						},
						{
							Name:    "profileparser",
							Image:   operatorImage,
							Command: profileparserCommand(pbNoCEL),
						},
					},
				},
			},
		},
	}

	if workloadNeedsUpdate(pbNoCEL, image, deplFromNoCEL) {
		t.Error("workloadNeedsUpdate should return false when spec matches deployment")
	}

	if !workloadNeedsUpdate(pbWithCEL, image, deplFromNoCEL) {
		t.Error("workloadNeedsUpdate should return true when celContentFile was added but deployment still has old commands")
	}
}
