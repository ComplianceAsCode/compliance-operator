// Package tlsconfig adapts OpenShift TLS profiles to CO's TLS servers.
package tlsconfig

import (
	"crypto/tls"

	configv1 "github.com/openshift/api/config/v1"
	tlspkg "github.com/openshift/controller-runtime-common/pkg/tls"
)

// NewTLSConfigFromProfile adds group support to the shared TLS helper on CO's
// Go 1.25 baseline. Cipher and version conversion remain with the shared helper.
// Unsupported ciphers and groups are returned for callers to log. Empty groups
// leave existing curve preferences unchanged.
//
// Go 1.26-only hybrid groups are treated as unsupported. This adapter can be
// removed when CO can consume a group-aware shared helper on its supported
// Go and Kubernetes baseline.
func NewTLSConfigFromProfile(profile configv1.TLSProfileSpec) (func(*tls.Config), []string) {
	configure, unsupported := tlspkg.NewTLSConfigFromProfile(profile)
	var curves []tls.CurveID
	for _, group := range profile.Groups {
		var curve tls.CurveID
		switch group {
		case configv1.TLSGroupSecP256r1:
			curve = tls.CurveP256
		case configv1.TLSGroupSecP384r1:
			curve = tls.CurveP384
		case configv1.TLSGroupSecP521r1:
			curve = tls.CurveP521
		case configv1.TLSGroupX25519:
			curve = tls.X25519
		case configv1.TLSGroupX25519MLKEM768:
			curve = tls.X25519MLKEM768
		default:
			unsupported = append(unsupported, string(group))
			continue
		}
		curves = append(curves, curve)
	}

	return func(c *tls.Config) {
		configure(c)
		if len(curves) > 0 {
			c.CurvePreferences = curves
		}
	}, unsupported
}
