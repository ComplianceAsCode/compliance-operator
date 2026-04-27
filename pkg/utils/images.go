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
	{"ghcr.io/complianceascode/openscap-ocp:v1.7.0", "RELATED_IMAGE_OPENSCAP"},
	{"ghcr.io/complianceascode/compliance-operator:v1.7.0", "RELATED_IMAGE_OPERATOR"},
	{"ghcr.io/complianceascode/k8scontent:b01ffe68cc1320ee472408798bc56d83cfbfb1f7", "RELATED_IMAGE_PROFILE"},
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
