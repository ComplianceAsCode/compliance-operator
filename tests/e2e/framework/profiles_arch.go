package framework

import (
	"context"
	"log"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// Architecture represents the cluster's node architecture for profile expectations.
type Architecture int

const (
	ArchAMD64 Architecture = iota
	ArchARM64
	ArchPPC64LE
	ArchS390X
	ArchMULTI
	ArchUNKNOWN
)

func (a Architecture) String() string {
	switch a {
	case ArchAMD64:
		return "amd64"
	case ArchARM64:
		return "arm64"
	case ArchPPC64LE:
		return "ppc64le"
	case ArchS390X:
		return "s390x"
	case ArchMULTI:
		return "multi"
	default:
		return "unknown"
	}
}

// ClusterArchitecture returns the cluster architecture from node status.
// If nodes report different architectures, returns ArchMULTI.
func (f *Framework) ClusterArchitecture() Architecture {
	nodeList := &corev1.NodeList{}
	if err := f.Client.List(context.TODO(), nodeList); err != nil {
		log.Printf("failed to list nodes: %v", err)
		return ArchUNKNOWN
	}
	archSet := make(map[string]struct{})
	for i := range nodeList.Items {
		arch := strings.ToLower(nodeList.Items[i].Status.NodeInfo.Architecture)
		if arch != "" {
			archSet[arch] = struct{}{}
		}
	}
	if len(archSet) == 0 {
		return ArchUNKNOWN
	}
	if len(archSet) > 1 {
		return ArchMULTI
	}
	var single string
	for a := range archSet {
		single = a
		break
	}
	switch single {
	case "amd64":
		return ArchAMD64
	case "arm64":
		return ArchARM64
	case "ppc64le":
		return ArchPPC64LE
	case "s390x":
		return ArchS390X
	default:
		return ArchUNKNOWN
	}
}

// Expected profiles per architecture (from compliance-operator-supported-profiles).
// MULTI and UNKNOWN have no single-arch list.
var (
	profilesS390X = []string{
		"ocp4-cis", "ocp4-cis-1-9", "ocp4-cis-node", "ocp4-cis-node-1-9",
		"ocp4-moderate", "ocp4-moderate-node", "ocp4-moderate-node-rev-4", "ocp4-moderate-rev-4",
		"ocp4-pci-dss", "ocp4-pci-dss-3-2", "ocp4-pci-dss-4-0", "ocp4-pci-dss-node",
		"ocp4-pci-dss-node-3-2", "ocp4-pci-dss-node-4-0",
	}
	profilesPPC64LE = []string{
		"ocp4-cis", "ocp4-cis-1-9", "ocp4-cis-node", "ocp4-cis-node-1-9",
		"ocp4-moderate", "ocp4-moderate-node", "ocp4-moderate-node-rev-4", "ocp4-moderate-rev-4",
		"ocp4-pci-dss", "ocp4-pci-dss-3-2", "ocp4-pci-dss-4-0", "ocp4-pci-dss-node",
		"ocp4-pci-dss-node-3-2", "ocp4-pci-dss-node-4-0",
		"rhcos4-moderate", "rhcos4-moderate-rev-4",
	}

	profilesAMD64 = []string{
		"ocp4-cis", "ocp4-cis-1-9", "ocp4-cis-node", "ocp4-cis-node-1-9",
		"ocp4-e8", "ocp4-high", "ocp4-high-node", "ocp4-high-node-rev-4", "ocp4-high-rev-4",
		"ocp4-moderate", "ocp4-moderate-node", "ocp4-moderate-node-rev-4", "ocp4-moderate-rev-4",
		"ocp4-nerc-cip", "ocp4-nerc-cip-node",
		"ocp4-pci-dss", "ocp4-pci-dss-3-2", "ocp4-pci-dss-4-0", "ocp4-pci-dss-node",
		"ocp4-pci-dss-node-3-2", "ocp4-pci-dss-node-4-0",
		"ocp4-stig", "ocp4-stig-node", "ocp4-stig-node-v2r2", "ocp4-stig-node-v2r3", "ocp4-stig-v2r2", "ocp4-stig-v2r3",
		"rhcos4-e8", "rhcos4-high", "rhcos4-high-rev-4", "rhcos4-moderate", "rhcos4-moderate-rev-4",
		"rhcos4-nerc-cip", "rhcos4-stig", "rhcos4-stig-v2r2", "rhcos4-stig-v2r3",
		"ocp4-bsi", "ocp4-bsi-2022", "ocp4-bsi-node", "ocp4-bsi-node-2022",
	}

	profilesARM64 = []string{
		"ocp4-cis", "ocp4-cis-1-9", "ocp4-cis-node", "ocp4-cis-node-1-9",
		"ocp4-moderate", "ocp4-moderate-node", "ocp4-moderate-node-rev-4", "ocp4-moderate-rev-4",
		"ocp4-pci-dss", "ocp4-pci-dss-3-2", "ocp4-pci-dss-4-0", "ocp4-pci-dss-node",
		"ocp4-pci-dss-node-3-2", "ocp4-pci-dss-node-4-0",
		"rhcos4-moderate", "rhcos4-moderate-rev-4",
	}

	profilesMULTI = []string{
		"ocp4-cis", "ocp4-cis-1-9", "ocp4-cis-node", "ocp4-cis-node-1-9",
		"ocp4-moderate", "ocp4-moderate-node", "ocp4-moderate-node-rev-4", "ocp4-moderate-rev-4",
		"ocp4-pci-dss", "ocp4-pci-dss-3-2", "ocp4-pci-dss-4-0", "ocp4-pci-dss-node",
		"ocp4-pci-dss-node-3-2", "ocp4-pci-dss-node-4-0",
		"rhcos4-moderate", "rhcos4-moderate-rev-4",
	}
)

// GetExpectedProfilesForArch returns the list of default profile names expected for the given
// architecture. Returns nil for ArchMULTI and ArchUNKNOWN (no single-arch list).
func GetExpectedProfilesForArch(arch Architecture) []string {
	switch arch {
	case ArchS390X:
		return profilesS390X
	case ArchPPC64LE:
		return profilesPPC64LE
	case ArchAMD64:
		return profilesAMD64
	case ArchARM64:
		return profilesARM64
	case ArchMULTI:
		return profilesMULTI
	default:
		return nil
	}
}
