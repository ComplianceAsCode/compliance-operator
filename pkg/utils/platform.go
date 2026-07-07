package utils

import (
	"os"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
)

const platformEnv = "PLATFORM"
const controlPlaneTopologyEnv = "CONTROL_PLANE_TOPOLOGY"

// HCP-related constants
const (
	// HCPComplianceNoteAnnotation is used to indicate HCP-specific compliance notes
	HCPComplianceNoteAnnotation = "compliance.openshift.io/hcp-note"
	// HCPControlPlaneNote is the message shown when running on a hosted cluster
	HCPControlPlaneNote = "Control plane compliance must be assessed from the management cluster. See documentation for HCP compliance setup: https://github.com/ComplianceAsCode/compliance-operator/blob/master/doc/usage.md#how-to-use-compliance-operator-with-hypershift-management-cluster"
)

// HCPInfo contains information about the HCP environment
type HCPInfo struct {
	// IsHCP indicates if this is a Hosted Control Plane environment
	IsHCP bool
	// ControlPlaneTopology is the control plane topology (External for HCP)
	ControlPlaneTopology string
	// IsManagementCluster indicates if this appears to be a management cluster
	IsManagementCluster bool
}

func GetPlatform() string {
	p := os.Getenv(platformEnv)
	if p == "" {
		return "OpenShift"
	}
	return p
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

// IsHyperShiftPlatform returns true if the platform is HyperShift
func IsHyperShiftPlatform() bool {
	return strings.EqualFold(GetPlatform(), "HyperShift")
}

// GetHCPInfo returns comprehensive information about the HCP environment
func GetHCPInfo() HCPInfo {
	topology := GetControlPlaneTopology()
	isHCP := IsHostedControlPlane()
	isHyperShiftPlatform := IsHyperShiftPlatform()

	return HCPInfo{
		IsHCP:                isHCP || isHyperShiftPlatform,
		ControlPlaneTopology: topology,
		IsManagementCluster:  !isHCP && !isHyperShiftPlatform,
	}
}

// GetHCPComplianceNote returns an appropriate compliance note for HCP environments
func GetHCPComplianceNote() string {
	if IsHostedControlPlane() || IsHyperShiftPlatform() {
		return HCPControlPlaneNote
	}
	return ""
}
