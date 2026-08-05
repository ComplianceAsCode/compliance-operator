package manager

import (
	"crypto/tls"

	configv1 "github.com/openshift/api/config/v1"
	tlspkg "github.com/openshift/controller-runtime-common/pkg/tls"
	libgocrypto "github.com/openshift/library-go/pkg/crypto"
)

// applyClusterTLSProfile conditionally applies the cluster TLS security
// profile to c. It is a no-op when the adherence policy does not require
// strict adherence. Returns any cipher suites unsupported by Go.
func applyClusterTLSProfile(c *tls.Config, profile configv1.TLSProfileSpec, adherence configv1.TLSAdherencePolicy) []string {
	if !libgocrypto.ShouldHonorClusterTLSProfile(adherence) {
		return nil
	}
	fn, unsupported := tlspkg.NewTLSConfigFromProfile(profile)
	fn(c)
	return unsupported
}
