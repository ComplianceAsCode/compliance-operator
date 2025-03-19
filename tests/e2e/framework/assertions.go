package framework

import (
	"context"
	"testing"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"

	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (f *Framework) AssertMustHaveParsedProfiles(t *testing.T, pbName, productType, productName string) {
	var l compv1alpha1.ProfileList
	o := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(map[string]string{
			compv1alpha1.ProfileBundleOwnerLabel: pbName,
		}),
	}
	if err := f.Client.List(context.TODO(), &l, o); err != nil {
		t.Fatalf("failed checking profiles in ProfileBundle: %s", err)
	}
	if len(l.Items) <= 0 {
		t.Fatalf("failed to get profiles from ProfileBundle %s. Expected at least one but got %d", pbName, len(l.Items))
	}

	for _, p := range l.Items {
		if p.Annotations[compv1alpha1.ProductTypeAnnotation] != productType {
			t.Fatalf("expected %s to be %s, got %s instead", compv1alpha1.ProductTypeAnnotation, productType, p.Annotations[compv1alpha1.ProductTypeAnnotation])
		}

		if p.Annotations[compv1alpha1.ProductAnnotation] != productName {
			t.Fatalf("expected %s to be %s, got %s instead", compv1alpha1.ProductAnnotation, productName, p.Annotations[compv1alpha1.ProductAnnotation])
		}
	}
}
