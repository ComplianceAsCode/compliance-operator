package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/stretchr/testify/require"
)

func TestNewTLSConfigFromProfile(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		version      configv1.TLSProtocolVersion
		minVersion   uint16
		cipherSuites []uint16
		groups       []configv1.TLSGroup
		curves       []tls.CurveID
	}{
		"TLS 1.2": {
			version:      configv1.VersionTLS12,
			minVersion:   tls.VersionTLS12,
			cipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			groups: []configv1.TLSGroup{
				configv1.TLSGroupSecP384r1, configv1.TLSGroupSecP256r1, configv1.TLSGroupSecP521r1,
			},
			curves: []tls.CurveID{tls.CurveP384, tls.CurveP256, tls.CurveP521},
		},
		"TLS 1.3": {
			version:    configv1.VersionTLS13,
			minVersion: tls.VersionTLS13,
			groups:     []configv1.TLSGroup{configv1.TLSGroupX25519MLKEM768, configv1.TLSGroupX25519},
			curves:     []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			configure, unsupported := NewTLSConfigFromProfile(configv1.TLSProfileSpec{
				MinTLSVersion: tc.version,
				Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256", "unknown-cipher"},
				Groups: append([]configv1.TLSGroup{
					"unknown-group", configv1.TLSGroupSecP256r1MLKEM768,
				}, tc.groups...),
			})
			require.Equal(t, []string{"unknown-cipher", "unknown-group", "SecP256r1MLKEM768"}, unsupported)

			clientCAs := x509.NewCertPool()
			c := &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs:  clientCAs,
				NextProtos: []string{"http/1.1"},
			}
			configure(c)
			require.Equal(t, tc.minVersion, c.MinVersion)
			require.Equal(t, tc.cipherSuites, c.CipherSuites)
			require.Equal(t, tc.curves, c.CurvePreferences)
			require.Equal(t, tls.RequireAndVerifyClientCert, c.ClientAuth)
			require.Same(t, clientCAs, c.ClientCAs)
			require.Equal(t, []string{"http/1.1"}, c.NextProtos)
		})
	}
}

func TestEmptyGroupsPreserveCurvePreferences(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		groups      []configv1.TLSGroup
		unsupported []string
	}{
		"unset": {},
		"empty": {groups: []configv1.TLSGroup{}},
		"unsupported": {
			groups:      []configv1.TLSGroup{"unknown-group"},
			unsupported: []string{"unknown-group"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			configure, unsupported := NewTLSConfigFromProfile(configv1.TLSProfileSpec{
				MinTLSVersion: configv1.VersionTLS12,
				Groups:        tc.groups,
			})
			require.Equal(t, tc.unsupported, unsupported)
			c := &tls.Config{CurvePreferences: []tls.CurveID{tls.CurveP384}}
			configure(c)
			require.Equal(t, []tls.CurveID{tls.CurveP384}, c.CurvePreferences)
		})
	}
}
