package common

import (
	"context"
	"crypto/tls"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	libgocrypto "github.com/openshift/library-go/pkg/crypto"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var tlsLog = logf.Log.WithName("tls-config")

// GetTLSProfileSpec resolves a TLSSecurityProfile to a concrete TLSProfileSpec.
// If the profile is nil or unrecognized, returns the Intermediate profile as
// the default per OpenShift conventions.
func GetTLSProfileSpec(profile *configv1.TLSSecurityProfile) *configv1.TLSProfileSpec {
	if profile == nil {
		return configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
	}
	switch profile.Type {
	case configv1.TLSProfileOldType:
		return configv1.TLSProfiles[configv1.TLSProfileOldType]
	case configv1.TLSProfileIntermediateType:
		return configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
	case configv1.TLSProfileModernType:
		return configv1.TLSProfiles[configv1.TLSProfileModernType]
	case configv1.TLSProfileCustomType:
		if profile.Custom != nil {
			return &profile.Custom.TLSProfileSpec
		}
		return configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
	default:
		return configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
	}
}

// TLSConfigFromProfile builds a *tls.Config from an OpenShift TLSSecurityProfile.
// It converts the profile's cipher suites from OpenSSL names to Go cipher suite
// IDs and resolves the minimum TLS version. The returned config disables HTTP/2
// by setting NextProtos to ["http/1.1"].
//
// TLS 1.3 cipher suites are excluded from CipherSuites because Go's crypto/tls
// always enables all TLS 1.3 ciphers and does not allow configuring them.
func TLSConfigFromProfile(profile *configv1.TLSSecurityProfile) (*tls.Config, error) {
	spec := GetTLSProfileSpec(profile)

	minVersion, err := libgocrypto.TLSVersion(string(spec.MinTLSVersion))
	if err != nil {
		return nil, fmt.Errorf("invalid minimum TLS version %q: %w", spec.MinTLSVersion, err)
	}

	ianaCiphers := libgocrypto.OpenSSLToIANACipherSuites(spec.Ciphers)

	// Filter to only TLS 1.2 cipher suites. TLS 1.3 suites are always
	// enabled by Go and cannot be configured, so we skip them here.
	var cipherSuites []uint16
	for _, name := range ianaCiphers {
		id, cipherErr := libgocrypto.CipherSuite(name)
		if cipherErr != nil {
			// TLS 1.3 ciphers and unknown ciphers are skipped
			continue
		}
		cipherSuites = append(cipherSuites, id)
	}
	if len(cipherSuites) == 0 {
		cipherSuites = libgocrypto.DefaultCiphers()
	}

	tlsLog.Info("Configuring TLS from cluster profile",
		"minVersion", spec.MinTLSVersion,
		"cipherCount", len(cipherSuites),
	)

	tlsConfig := &tls.Config{
		MinVersion:   minVersion,
		CipherSuites: cipherSuites,
		NextProtos:   []string{"http/1.1"},
	}
	return tlsConfig, nil
}

// GetClusterTLSProfile fetches the APIServer resource using the provided
// Kubernetes client and returns the TLS security profile if the tlsAdherence
// policy requires strict adherence. Returns nil if the profile should not be
// enforced (legacy mode, resource not found, or errors fetching it).
func GetClusterTLSProfile(ctx context.Context, kClient kubernetes.Interface) *configv1.TLSSecurityProfile {
	apiServer := &configv1.APIServer{}
	err := kClient.Discovery().RESTClient().Get().
		RequestURI("/apis/config.openshift.io/v1/apiservers/cluster").
		Do(ctx).Into(apiServer)
	if err != nil {
		tlsLog.Info("Could not fetch APIServer resource for TLS profile, using defaults")
		return nil
	}
	return extractTLSProfile(apiServer)
}

// FetchInClusterTLSProfile builds a Kubernetes client from in-cluster config
// and returns the cluster TLS security profile if strict adherence is required.
// Returns nil when not running in a cluster, on errors, or if the adherence
// policy does not require it.
func FetchInClusterTLSProfile() *configv1.TLSSecurityProfile {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		tlsLog.Info("Not running in cluster, skipping cluster TLS profile lookup")
		return nil
	}
	kClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		tlsLog.Info("Could not create Kubernetes client for TLS profile lookup")
		return nil
	}
	return GetClusterTLSProfile(context.Background(), kClient)
}

// extractTLSProfile checks the adherence policy and returns the TLS profile
// from the APIServer resource.
func extractTLSProfile(apiServer *configv1.APIServer) *configv1.TLSSecurityProfile {
	if !libgocrypto.ShouldHonorClusterTLSProfile(apiServer.Spec.TLSAdherence) {
		tlsLog.Info("Cluster TLS adherence policy does not require strict adherence, using defaults")
		return nil
	}

	if apiServer.Spec.TLSSecurityProfile == nil {
		tlsLog.Info("Cluster TLS adherence is strict but no TLS profile is set, using Intermediate default")
		return &configv1.TLSSecurityProfile{
			Type: configv1.TLSProfileIntermediateType,
		}
	}

	tlsLog.Info("Using cluster TLS security profile",
		"profileType", apiServer.Spec.TLSSecurityProfile.Type)
	return apiServer.Spec.TLSSecurityProfile
}
