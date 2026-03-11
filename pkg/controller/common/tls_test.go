package common

import (
	"crypto/tls"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestExtractTLSProfile(t *testing.T) {
	tests := []struct {
		name        string
		apiServer   *configv1.APIServer
		expectNil   bool
		profileType configv1.TLSProfileType
	}{
		{
			name: "no opinion returns nil",
			apiServer: &configv1.APIServer{
				Spec: configv1.APIServerSpec{
					TLSAdherence: configv1.TLSAdherencePolicyNoOpinion,
				},
			},
			expectNil: true,
		},
		{
			name: "legacy returns nil",
			apiServer: &configv1.APIServer{
				Spec: configv1.APIServerSpec{
					TLSAdherence: configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly,
				},
			},
			expectNil: true,
		},
		{
			name: "strict with no profile returns Intermediate default",
			apiServer: &configv1.APIServer{
				Spec: configv1.APIServerSpec{
					TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
				},
			},
			expectNil:   false,
			profileType: configv1.TLSProfileIntermediateType,
		},
		{
			name: "strict with Modern profile returns Modern",
			apiServer: &configv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.APIServerSpec{
					TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
					ServingCerts: configv1.APIServerServingCerts{},
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileModernType,
					},
				},
			},
			expectNil:   false,
			profileType: configv1.TLSProfileModernType,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTLSProfile(tt.apiServer)
			if tt.expectNil {
				if got != nil {
					t.Errorf("extractTLSProfile() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("extractTLSProfile() = nil, want non-nil")
			}
			if got.Type != tt.profileType {
				t.Errorf("extractTLSProfile().Type = %v, want %v", got.Type, tt.profileType)
			}
		})
	}
}

func TestGetTLSProfileSpec(t *testing.T) {
	tests := []struct {
		name               string
		profile            *configv1.TLSSecurityProfile
		expectedMinVersion configv1.TLSProtocolVersion
	}{
		{
			name:               "nil profile returns Intermediate",
			profile:            nil,
			expectedMinVersion: configv1.VersionTLS12,
		},
		{
			name:               "Old profile",
			profile:            &configv1.TLSSecurityProfile{Type: configv1.TLSProfileOldType},
			expectedMinVersion: configv1.VersionTLS10,
		},
		{
			name:               "Intermediate profile",
			profile:            &configv1.TLSSecurityProfile{Type: configv1.TLSProfileIntermediateType},
			expectedMinVersion: configv1.VersionTLS12,
		},
		{
			name:               "Modern profile",
			profile:            &configv1.TLSSecurityProfile{Type: configv1.TLSProfileModernType},
			expectedMinVersion: configv1.VersionTLS13,
		},
		{
			name: "Custom profile",
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
						MinTLSVersion: configv1.VersionTLS12,
					},
				},
			},
			expectedMinVersion: configv1.VersionTLS12,
		},
		{
			name: "Custom profile with nil custom field falls back to Intermediate",
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
			},
			expectedMinVersion: configv1.VersionTLS12,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := GetTLSProfileSpec(tt.profile)
			if spec.MinTLSVersion != tt.expectedMinVersion {
				t.Errorf("GetTLSProfileSpec() MinTLSVersion = %v, want %v", spec.MinTLSVersion, tt.expectedMinVersion)
			}
		})
	}
}

func TestTLSConfigFromProfile(t *testing.T) {
	tests := []struct {
		name               string
		profile            *configv1.TLSSecurityProfile
		expectedMinVersion uint16
		expectError        bool
	}{
		{
			name:               "nil profile uses Intermediate defaults",
			profile:            nil,
			expectedMinVersion: tls.VersionTLS12,
		},
		{
			name:               "Intermediate profile",
			profile:            &configv1.TLSSecurityProfile{Type: configv1.TLSProfileIntermediateType},
			expectedMinVersion: tls.VersionTLS12,
		},
		{
			name:               "Old profile uses TLS 1.0",
			profile:            &configv1.TLSSecurityProfile{Type: configv1.TLSProfileOldType},
			expectedMinVersion: tls.VersionTLS10,
		},
		{
			name:               "Modern profile uses TLS 1.3",
			profile:            &configv1.TLSSecurityProfile{Type: configv1.TLSProfileModernType},
			expectedMinVersion: tls.VersionTLS13,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := TLSConfigFromProfile(tt.profile)
			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if cfg.MinVersion != tt.expectedMinVersion {
				t.Errorf("MinVersion = %d, want %d", cfg.MinVersion, tt.expectedMinVersion)
			}
			if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "http/1.1" {
				t.Errorf("NextProtos = %v, want [http/1.1]", cfg.NextProtos)
			}
		})
	}
}
