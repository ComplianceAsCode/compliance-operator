package utils

import (
	"os"
	goruntime "runtime"
	"strings"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	configv1 "github.com/openshift/api/config/v1"
)

type PlatformType string

const (
	platformEnv                           = "PLATFORM"
	controlPlaneTopologyEnv               = "CONTROL_PLANE_TOPOLOGY"
	PlatformOpenShift        PlatformType = "OpenShift"
	PlatformEKS              PlatformType = "EKS"
	PlatformROSA             PlatformType = "ROSA"
	PlatformGeneric          PlatformType = "Generic"
	PlatformHyperShift       PlatformType = "HyperShift"
	PlatformOpenShiftOnPower PlatformType = "OpenShiftOnPower"
	PlatformOpenShiftOnZ     PlatformType = "OpenShiftOnZ"
	PlatformUnknown          PlatformType = "Unknown"
)

var (
	defaultRolesPerPlatform = map[PlatformType][]string{
		PlatformOpenShift: {
			"master",
			"worker",
		},
		PlatformOpenShiftOnPower: {
			"master",
			"worker",
		},
		PlatformOpenShiftOnZ: {
			"master",
			"worker",
		},
		PlatformGeneric: {
			compv1alpha1.AllRoles,
		},
		PlatformHyperShift: {
			"worker",
		},
		PlatformROSA: {
			"worker",
		},
	}
	defaultAutoRemediationPerPlatform = map[PlatformType]bool{
		PlatformOpenShift:        true,
		PlatformOpenShiftOnPower: true,
		PlatformOpenShiftOnZ:     true,
		PlatformEKS:              false,
		PlatformGeneric:          false,
		PlatformHyperShift:       true,
		PlatformROSA:             false,
	}
	defaultProductsPerPlatform = map[PlatformType][]string{
		PlatformOpenShift: {
			"rhcos4",
			"ocp4",
		},
		PlatformOpenShiftOnPower: {
			"rhcos4",
			"ocp4",
		},
		PlatformOpenShiftOnZ: {"ocp4"},
		PlatformEKS: {
			"eks",
		},
		PlatformHyperShift: {
			"rhcos4",
			"ocp4",
		},
		PlatformROSA: {
			"rhcos4",
			"ocp4",
		},
	}
)

func GetPlatform() string {
	p := os.Getenv(platformEnv)
	if p == "" {
		return "OpenShift"
	}
	return p
}

func GetValidPlatform() PlatformType {
	p := GetPlatform()
	return validatePlatformString(p)
}

func GetValidPlatformFromString(p string) PlatformType {
	return validatePlatformString(p)
}

func validatePlatformString(p string) PlatformType {
	arch := goruntime.GOARCH
	switch {
	case strings.EqualFold(p, string(PlatformOpenShift)):
		switch {
		case strings.EqualFold(arch, "ppc64le"):
			return PlatformOpenShiftOnPower
		case strings.EqualFold(arch, "s390x"):
			return PlatformOpenShiftOnZ
		default:
			return PlatformOpenShift
		}
	case strings.EqualFold(p, string(PlatformROSA)):
		return PlatformROSA
	case strings.EqualFold(p, string(PlatformEKS)):
		return PlatformEKS
	case strings.EqualFold(p, string(PlatformHyperShift)):
		return PlatformHyperShift
	case strings.EqualFold(p, string(PlatformROSA)):
		return PlatformROSA
	case strings.EqualFold(p, string(PlatformGeneric)):
		return PlatformGeneric

	default:
		return PlatformUnknown
	}
}

func GetDefaultRolesForPlatform(p PlatformType) []string {
	return defaultRolesPerPlatform[p]
}

func GetDefaultProductsForPlatform(p PlatformType) ([]string, bool) {
	defaultProducts, isSupported := defaultProductsPerPlatform[p]
	return defaultProducts, isSupported
}

func GetControlPlaneTopology() string {
	return os.Getenv(controlPlaneTopologyEnv)
}

func IsHostedControlPlane() bool {
	topology := GetControlPlaneTopology()
	if strings.EqualFold(topology, string(configv1.ExternalTopologyMode)) {
		return true
	} else {
		return false
	}
}

func PlatformSupportsAutoRemediation(p PlatformType) bool {
	return defaultAutoRemediationPerPlatform[p]
}
