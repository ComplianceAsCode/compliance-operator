package utils

import (
	"os"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestGetPlatform(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected string
	}{
		{
			name:     "default to OpenShift when env not set",
			envValue: "",
			expected: "OpenShift",
		},
		{
			name:     "return HyperShift when set",
			envValue: "HyperShift",
			expected: "HyperShift",
		},
		{
			name:     "return ROSA when set",
			envValue: "ROSA",
			expected: "ROSA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				os.Setenv(platformEnv, tt.envValue)
				defer os.Unsetenv(platformEnv)
			} else {
				os.Unsetenv(platformEnv)
			}

			result := GetPlatform()
			if result != tt.expected {
				t.Errorf("GetPlatform() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsHostedControlPlane(t *testing.T) {
	tests := []struct {
		name     string
		topology string
		expected bool
	}{
		{
			name:     "external topology is HCP",
			topology: string(configv1.ExternalTopologyMode),
			expected: true,
		},
		{
			name:     "highly available is not HCP",
			topology: string(configv1.HighlyAvailableTopologyMode),
			expected: false,
		},
		{
			name:     "single replica is not HCP",
			topology: string(configv1.SingleReplicaTopologyMode),
			expected: false,
		},
		{
			name:     "empty is not HCP",
			topology: "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv(controlPlaneTopologyEnv, tt.topology)
			defer os.Unsetenv(controlPlaneTopologyEnv)

			result := IsHostedControlPlane()
			if result != tt.expected {
				t.Errorf("IsHostedControlPlane() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsHyperShiftPlatform(t *testing.T) {
	tests := []struct {
		name     string
		platform string
		expected bool
	}{
		{
			name:     "HyperShift platform",
			platform: "HyperShift",
			expected: true,
		},
		{
			name:     "hypershift lowercase",
			platform: "hypershift",
			expected: true,
		},
		{
			name:     "OpenShift platform",
			platform: "OpenShift",
			expected: false,
		},
		{
			name:     "ROSA platform",
			platform: "ROSA",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv(platformEnv, tt.platform)
			defer os.Unsetenv(platformEnv)

			result := IsHyperShiftPlatform()
			if result != tt.expected {
				t.Errorf("IsHyperShiftPlatform() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetHCPInfo(t *testing.T) {
	tests := []struct {
		name                string
		platform            string
		topology            string
		expectedIsHCP       bool
		expectedIsMgmtClstr bool
	}{
		{
			name:                "HyperShift platform with external topology",
			platform:            "HyperShift",
			topology:            string(configv1.ExternalTopologyMode),
			expectedIsHCP:       true,
			expectedIsMgmtClstr: false,
		},
		{
			name:                "HyperShift platform without external topology",
			platform:            "HyperShift",
			topology:            "",
			expectedIsHCP:       true,
			expectedIsMgmtClstr: false,
		},
		{
			name:                "OpenShift with external topology (hosted cluster)",
			platform:            "OpenShift",
			topology:            string(configv1.ExternalTopologyMode),
			expectedIsHCP:       true,
			expectedIsMgmtClstr: false,
		},
		{
			name:                "OpenShift management cluster",
			platform:            "OpenShift",
			topology:            string(configv1.HighlyAvailableTopologyMode),
			expectedIsHCP:       false,
			expectedIsMgmtClstr: true,
		},
		{
			name:                "standard OpenShift cluster",
			platform:            "OpenShift",
			topology:            "",
			expectedIsHCP:       false,
			expectedIsMgmtClstr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv(platformEnv, tt.platform)
			os.Setenv(controlPlaneTopologyEnv, tt.topology)
			defer os.Unsetenv(platformEnv)
			defer os.Unsetenv(controlPlaneTopologyEnv)

			info := GetHCPInfo()
			if info.IsHCP != tt.expectedIsHCP {
				t.Errorf("GetHCPInfo().IsHCP = %v, want %v", info.IsHCP, tt.expectedIsHCP)
			}
			if info.IsManagementCluster != tt.expectedIsMgmtClstr {
				t.Errorf("GetHCPInfo().IsManagementCluster = %v, want %v", info.IsManagementCluster, tt.expectedIsMgmtClstr)
			}
		})
	}
}

func TestGetHCPComplianceNote(t *testing.T) {
	tests := []struct {
		name        string
		platform    string
		topology    string
		expectEmpty bool
	}{
		{
			name:        "HyperShift platform should return note",
			platform:    "HyperShift",
			topology:    "",
			expectEmpty: false,
		},
		{
			name:        "external topology should return note",
			platform:    "OpenShift",
			topology:    string(configv1.ExternalTopologyMode),
			expectEmpty: false,
		},
		{
			name:        "standard OpenShift should return empty",
			platform:    "OpenShift",
			topology:    "",
			expectEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv(platformEnv, tt.platform)
			os.Setenv(controlPlaneTopologyEnv, tt.topology)
			defer os.Unsetenv(platformEnv)
			defer os.Unsetenv(controlPlaneTopologyEnv)

			note := GetHCPComplianceNote()
			if tt.expectEmpty && note != "" {
				t.Errorf("GetHCPComplianceNote() = %v, want empty", note)
			}
			if !tt.expectEmpty && note == "" {
				t.Errorf("GetHCPComplianceNote() = empty, want non-empty")
			}
		})
	}
}
