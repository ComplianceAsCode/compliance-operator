package utils

import "os"

type ComplianceComponent uint

const (
	OPENSCAP = iota
	OPERATOR
	CONTENT
)

var componentDefaults = []struct {
	defaultImage string
	envVar       string
}{
	{"quay.io/redhat-user-workloads/ocp-isc-tenant/compliance-operator-openscap-release:release-1.10", "RELATED_IMAGE_OPENSCAP"},
	{"quay.io/redhat-user-workloads/ocp-isc-tenant/compliance-operator-release:release-1.10", "RELATED_IMAGE_OPERATOR"},
	{"quay.io/redhat-user-workloads/ocp-isc-tenant/compliance-operator-content-release:release-1.10", "RELATED_IMAGE_PROFILE"},
}

// GetComponentImage returns a full image pull spec for a given component
// based on the component type
func GetComponentImage(component ComplianceComponent) string {
	comp := componentDefaults[component]

	imageTag := os.Getenv(comp.envVar)
	if imageTag == "" {
		imageTag = comp.defaultImage
	}
	return imageTag
}
