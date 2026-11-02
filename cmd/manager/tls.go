package manager

import (
	"context"
	"crypto/tls"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	tlspkg "github.com/openshift/controller-runtime-common/pkg/tls"
	libgocrypto "github.com/openshift/library-go/pkg/crypto"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// tlsLookupTimeout bounds the cluster TLS profile/adherence lookups so an
// unresponsive API server cannot block operator startup or the result server
// indefinitely; on timeout the caller falls back to secure defaults.
const tlsLookupTimeout = 30 * time.Second

// fetchClusterTLSState fetches the cluster's TLS security profile and adherence
// policy from the APIServer resource using c, bounding both lookups with
// tlsLookupTimeout (a child of ctx). On any lookup error it falls back to
// secure defaults (default ciphers/min version and a "no opinion" adherence
// policy) so callers always receive a usable pair.
func fetchClusterTLSState(ctx context.Context, c client.Client) (configv1.TLSProfileSpec, configv1.TLSAdherencePolicy) {
	lookupCtx, cancel := context.WithTimeout(ctx, tlsLookupTimeout)
	defer cancel()

	profile, err := tlspkg.FetchAPIServerTLSProfile(lookupCtx, c)
	if err != nil {
		cmdLog.Info("Could not fetch APIServer TLS profile, using defaults", "error", err)
		profile = configv1.TLSProfileSpec{
			Ciphers:       tlspkg.DefaultTLSCiphers,
			MinTLSVersion: tlspkg.DefaultMinTLSVersion,
		}
	}

	adherence, err := tlspkg.FetchAPIServerTLSAdherencePolicy(lookupCtx, c)
	if err != nil {
		cmdLog.Info("Could not fetch APIServer TLS adherence policy, using defaults", "error", err)
		adherence = configv1.TLSAdherencePolicyNoOpinion
	}

	return profile, adherence
}

// applyClusterTLSProfile conditionally applies the cluster TLS security
// profile to c. It is a no-op when the adherence policy does not require
// strict adherence. Returns any cipher suites or groups unsupported by Go.
func applyClusterTLSProfile(c *tls.Config, profile configv1.TLSProfileSpec, adherence configv1.TLSAdherencePolicy) []string {
	if !libgocrypto.ShouldHonorClusterTLSProfile(adherence) {
		return nil
	}
	fn, unsupported := tlspkg.NewTLSConfigFromProfile(profile)
	fn(c)
	return unsupported
}
