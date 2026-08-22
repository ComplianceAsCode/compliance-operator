package framework

// ExpectsRhcos4ProfileBundle reports whether the cluster architecture should have a rhcos4 ProfileBundle.
func ExpectsRhcos4ProfileBundle(arch Architecture) bool {
	switch arch {
	case ArchAMD64, ArchARM64, ArchPPC64LE, ArchMULTI:
		return true
	default:
		return false
	}
}

// Expected profiles per architecture (from compliance-operator-supported-profiles).
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
// architecture. Returns nil for ArchUNKNOWN (unrecognized architecture).
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
