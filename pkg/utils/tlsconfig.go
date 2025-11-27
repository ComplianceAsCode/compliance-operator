package utils

import (
	"context"
	"crypto/tls"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	libgocrypto "github.com/openshift/library-go/pkg/crypto"
)

var tlsLog = logf.Log.WithName("tlsconfig")

// TLSVersion maps OpenShift TLS protocol versions to Go's tls constants
var TLSVersionMapping = map[configv1.TLSProtocolVersion]uint16{
	configv1.VersionTLS10: tls.VersionTLS10,
	configv1.VersionTLS11: tls.VersionTLS11,
	configv1.VersionTLS12: tls.VersionTLS12,
	configv1.VersionTLS13: tls.VersionTLS13,
}

// GetAPIServerTLSConfig fetches the TLS security profile from the OpenShift APIServer resource
// and returns a properly configured tls.Config. If the APIServer resource is not available
// or not accessible, it falls back to secure defaults (TLS 1.2 + secure cipher suites).
//
// This function respects cluster-wide TLS policies configured by administrators,
// including support for TLS 1.3 when Modern profile is set (for post-quantum readiness).
func GetAPIServerTLSConfig(ctx context.Context, cfg *rest.Config) (*tls.Config, error) {
	// Create a client to access the OpenShift config API
	cl, err := client.New(cfg, client.Options{})
	if err != nil {
		tlsLog.Info("Unable to create client for APIServer config, using secure defaults",
			"error", err.Error())
		return getDefaultTLSConfig(), nil
	}

	// Fetch the cluster APIServer configuration
	apiServer := &configv1.APIServer{}
	err = cl.Get(ctx, types.NamespacedName{Name: "cluster"}, apiServer)
	if err != nil {
		if errors.IsNotFound(err) {
			tlsLog.Info("APIServer 'cluster' resource not found, using secure defaults",
				"note", "this is normal on non-OpenShift clusters")
		} else {
			tlsLog.Info("Unable to fetch APIServer config, using secure defaults",
				"error", err.Error())
		}
		return getDefaultTLSConfig(), nil
	}

	// Extract TLS configuration from the APIServer spec
	tlsProfile := apiServer.Spec.TLSSecurityProfile
	tlsConfig, err := getTLSConfigFromProfile(tlsProfile)
	if err != nil {
		tlsLog.Error(err, "Error parsing TLS security profile, using secure defaults")
		return getDefaultTLSConfig(), nil
	}

	profileType := "Intermediate (default)"
	if tlsProfile != nil {
		profileType = string(tlsProfile.Type)
	}
	tlsLog.Info("Successfully configured TLS from cluster APIServer",
		"profile", profileType,
		"minTLSVersion", getTLSVersionString(tlsConfig.MinVersion))

	return tlsConfig, nil
}

// getTLSConfigFromProfile converts an OpenShift TLSSecurityProfile to a Go tls.Config
func getTLSConfigFromProfile(profile *configv1.TLSSecurityProfile) (*tls.Config, error) {
	var profileSpec *configv1.TLSProfileSpec

	// Determine which profile to use
	if profile == nil {
		// No profile specified, use Intermediate (secure default)
		profileSpec = configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
	} else {
		switch profile.Type {
		case configv1.TLSProfileOldType:
			profileSpec = configv1.TLSProfiles[configv1.TLSProfileOldType]
		case configv1.TLSProfileIntermediateType:
			profileSpec = configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
		case configv1.TLSProfileModernType:
			// Modern profile uses TLS 1.3 only
			profileSpec = configv1.TLSProfiles[configv1.TLSProfileModernType]
		case configv1.TLSProfileCustomType:
			if profile.Custom != nil {
				profileSpec = &profile.Custom.TLSProfileSpec
			} else {
				// Custom type but no spec, fall back to Intermediate
				profileSpec = configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
			}
		default:
			// Unknown profile type, use Intermediate
			profileSpec = configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
		}
	}

	if profileSpec == nil {
		return nil, fmt.Errorf("unable to determine TLS profile spec")
	}

	// Convert OpenShift TLS version to Go tls constant
	minVersion, ok := TLSVersionMapping[profileSpec.MinTLSVersion]
	if !ok {
		return nil, fmt.Errorf("unknown TLS version: %s", profileSpec.MinTLSVersion)
	}

	// Convert OpenShift cipher suite names (OpenSSL format) to Go tls constants (IANA format)
	ianaCipherSuites := libgocrypto.OpenSSLToIANACipherSuites(profileSpec.Ciphers)
	cipherSuiteIDs := libgocrypto.CipherSuitesOrDie(ianaCipherSuites)

	// Create the base TLS config
	tlsConfig := &tls.Config{
		MinVersion:   minVersion,
		CipherSuites: cipherSuiteIDs,
	}

	// Apply additional security hardening via library-go
	tlsConfig = libgocrypto.SecureTLSConfig(tlsConfig)

	return tlsConfig, nil
}

// getDefaultTLSConfig returns a secure default TLS configuration
// This is used as a fallback when the APIServer config is unavailable
func getDefaultTLSConfig() *tls.Config {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	// Apply security hardening with default cipher suites
	return libgocrypto.SecureTLSConfig(tlsConfig)
}

// getTLSVersionString converts a TLS version constant to a human-readable string
func getTLSVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%x)", version)
	}
}

// GetAPIServerTLSConfigOrDefault is a convenience wrapper that returns a TLS config
// from the APIServer, or a secure default if any error occurs.
// This function never returns an error, making it safe to use in server initialization.
func GetAPIServerTLSConfigOrDefault(ctx context.Context, cfg *rest.Config) *tls.Config {
	tlsConfig, err := GetAPIServerTLSConfig(ctx, cfg)
	if err != nil {
		tlsLog.Info("Using default TLS configuration")
		return getDefaultTLSConfig()
	}
	return tlsConfig
}
