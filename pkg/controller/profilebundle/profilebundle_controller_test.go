package profilebundle

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	compliancev1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
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
