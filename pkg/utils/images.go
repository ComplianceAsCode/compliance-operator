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
	{"quay.io/redhat-user-workloads/ocp-isc-tenant/compliance-operator-openscap-dev:master", "RELATED_IMAGE_OPENSCAP"},
	{"quay.io/redhat-user-workloads/ocp-isc-tenant/compliance-operator-dev:master", "RELATED_IMAGE_OPERATOR"},
	{"quay.io/redhat-user-workloads/ocp-isc-tenant/compliance-operator-content-dev:master", "RELATED_IMAGE_PROFILE"},
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
