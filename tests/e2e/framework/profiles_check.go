package framework

import (
	"errors"
	"fmt"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
)

// CheckNodeOnlyProfiles returns an error unless every Profile is a node
// Profile and each of the given ProfileBundles parsed at least one of them,
// as on ROSA HCP, where the operator parses only node Profiles. An empty list
// is an error: it means that nothing was parsed, not that the check passed.
func CheckNodeOnlyProfiles(profiles []compv1alpha1.Profile, bundles ...string) error {
	if len(profiles) == 0 {
		return errors.New("no Profiles were parsed")
	}
	fromBundle := map[string]int{}
	for _, p := range profiles {
		if pt := p.Annotations[compv1alpha1.ProductTypeAnnotation]; pt != "Node" {
			return fmt.Errorf("found an unexpected profile type: %s of type %s", p.GetName(), pt)
		}
		fromBundle[p.Labels[compv1alpha1.ProfileBundleOwnerLabel]]++
	}
	for _, bundle := range bundles {
		if fromBundle[bundle] == 0 {
			return fmt.Errorf("no Profiles were parsed from the %s ProfileBundle", bundle)
		}
	}
	return nil
}
