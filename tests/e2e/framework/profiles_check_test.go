package framework

import (
	"testing"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func profileFrom(name, bundle, productType string) compv1alpha1.Profile {
	return compv1alpha1.Profile{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Labels:      map[string]string{compv1alpha1.ProfileBundleOwnerLabel: bundle},
			Annotations: map[string]string{compv1alpha1.ProductTypeAnnotation: productType},
		},
	}
}

func TestCheckNodeOnlyProfiles(t *testing.T) {
	tests := []struct {
		name     string
		profiles []compv1alpha1.Profile
		wantErr  bool
	}{
		{
			name:     "no Profiles were parsed",
			profiles: nil,
			wantErr:  true,
		},
		{
			name: "a platform Profile was parsed",
			profiles: []compv1alpha1.Profile{
				profileFrom("ocp4-cis", "ocp4", "Platform"),
				profileFrom("ocp4-cis-node", "ocp4", "Node"),
				profileFrom("rhcos4-e8", "rhcos4", "Node"),
			},
			wantErr: true,
		},
		{
			name: "one ProfileBundle parsed nothing",
			profiles: []compv1alpha1.Profile{
				profileFrom("ocp4-cis-node", "ocp4", "Node"),
			},
			wantErr: true,
		},
		{
			name: "both ProfileBundles parsed only node Profiles",
			profiles: []compv1alpha1.Profile{
				profileFrom("ocp4-cis-node", "ocp4", "Node"),
				profileFrom("rhcos4-e8", "rhcos4", "Node"),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckNodeOnlyProfiles(tt.profiles, "ocp4", "rhcos4")
			if (err != nil) != tt.wantErr {
				t.Fatalf("CheckNodeOnlyProfiles() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
