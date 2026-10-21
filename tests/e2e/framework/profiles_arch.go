package framework

// ExpectsRhcos4ProfileBundle returns true when the given architecture
// should have the rhcos4 ProfileBundle installed.
func ExpectsRhcos4ProfileBundle(arch Architecture) bool {
	switch arch {
	case ArchAMD64, ArchARM64, ArchPPC64LE, ArchMULTI:
		return true
	default:
		return false
	}
}

// GetExpectedProfilesForArch returns the list of Profile names that must
// exist after installation for the given cluster architecture.
func GetExpectedProfilesForArch(arch Architecture) []string {
	switch arch {
	case ArchS390X:
		return s390xProfiles
	case ArchPPC64LE:
		return ppc64leProfiles
	case ArchARM64:
		return arm64Profiles
	case ArchMULTI:
		return multiProfiles
	default:
		return amd64Profiles
	}
}

var s390xProfiles = []string{
	"ocp4-cis",
	"ocp4-cis-1-9",
	"ocp4-cis-node",
	"ocp4-cis-node-1-9",
	"ocp4-moderate",
	"ocp4-moderate-node",
	"ocp4-moderate-node-rev-4",
	"ocp4-moderate-rev-4",
	"ocp4-pci-dss",
	"ocp4-pci-dss-3-2",
	"ocp4-pci-dss-4-0",
	"ocp4-pci-dss-node",
	"ocp4-pci-dss-node-3-2",
	"ocp4-pci-dss-node-4-0",
}

var ppc64leProfiles = []string{
	"ocp4-cis",
	"ocp4-cis-1-9",
	"ocp4-cis-node",
	"ocp4-cis-node-1-9",
	"ocp4-moderate",
	"ocp4-moderate-node",
	"ocp4-moderate-node-rev-4",
	"ocp4-moderate-rev-4",
	"ocp4-pci-dss",
	"ocp4-pci-dss-3-2",
	"ocp4-pci-dss-4-0",
	"ocp4-pci-dss-node",
	"ocp4-pci-dss-node-3-2",
	"ocp4-pci-dss-node-4-0",
	"rhcos4-moderate",
	"rhcos4-moderate-rev-4",
}

var arm64Profiles = []string{
	"ocp4-cis",
	"ocp4-cis-1-9",
	"ocp4-cis-node",
	"ocp4-cis-node-1-9",
	"ocp4-moderate",
	"ocp4-moderate-node",
	"ocp4-moderate-node-rev-4",
	"ocp4-moderate-rev-4",
	"ocp4-pci-dss",
	"ocp4-pci-dss-3-2",
	"ocp4-pci-dss-4-0",
	"ocp4-pci-dss-node",
	"ocp4-pci-dss-node-3-2",
	"ocp4-pci-dss-node-4-0",
	"rhcos4-moderate",
	"rhcos4-moderate-rev-4",
}

var multiProfiles = []string{
	"ocp4-cis",
	"ocp4-cis-1-9",
	"ocp4-cis-node",
	"ocp4-cis-node-1-9",
	"ocp4-moderate",
	"ocp4-moderate-node",
	"ocp4-moderate-node-rev-4",
	"ocp4-moderate-rev-4",
	"ocp4-pci-dss",
	"ocp4-pci-dss-3-2",
	"ocp4-pci-dss-4-0",
	"ocp4-pci-dss-node",
	"ocp4-pci-dss-node-3-2",
	"ocp4-pci-dss-node-4-0",
	"rhcos4-moderate",
	"rhcos4-moderate-rev-4",
}

var amd64Profiles = []string{
	"ocp4-cis",
	"ocp4-cis-1-9",
	"ocp4-cis-node",
	"ocp4-cis-node-1-9",
	"ocp4-e8",
	"ocp4-high",
	"ocp4-high-node",
	"ocp4-high-node-rev-4",
	"ocp4-high-rev-4",
	"ocp4-moderate",
	"ocp4-moderate-node",
	"ocp4-moderate-node-rev-4",
	"ocp4-moderate-rev-4",
	"ocp4-nerc-cip",
	"ocp4-nerc-cip-node",
	"ocp4-pci-dss",
	"ocp4-pci-dss-3-2",
	"ocp4-pci-dss-4-0",
	"ocp4-pci-dss-node",
	"ocp4-pci-dss-node-3-2",
	"ocp4-pci-dss-node-4-0",
	"ocp4-stig",
	"ocp4-stig-node",
	"ocp4-bsi",
	"ocp4-bsi-node",
	"rhcos4-e8",
	"rhcos4-high",
	"rhcos4-high-rev-4",
	"rhcos4-moderate",
	"rhcos4-moderate-rev-4",
	"rhcos4-nerc-cip",
	"rhcos4-stig",
	"rhcos4-bsi",
}
