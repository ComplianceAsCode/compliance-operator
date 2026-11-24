package manager

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	configv1 "github.com/openshift/api/config/v1"
	tlspkg "github.com/openshift/controller-runtime-common/pkg/tls"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("fetchClusterTLSState", func() {
	Context("when the APIServer resource specifies a profile and adherence policy", func() {
		It("returns the configured profile and adherence policy", func() {
			apiServer := &configv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: tlspkg.APIServerName},
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileModernType,
					},
					TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
				},
			}
			cl := fake.NewClientBuilder().WithScheme(operatorScheme).WithObjects(apiServer).Build()

			profile, adherence := fetchClusterTLSState(context.Background(), cl)
			Expect(adherence).To(Equal(configv1.TLSAdherencePolicyStrictAllComponents))
			Expect(profile.MinTLSVersion).To(Equal(configv1.TLSProfiles[configv1.TLSProfileModernType].MinTLSVersion))
		})
	})

	Context("when the APIServer resource is missing", func() {
		It("falls back to secure defaults and a no-opinion adherence policy", func() {
			cl := fake.NewClientBuilder().WithScheme(operatorScheme).Build()

			profile, adherence := fetchClusterTLSState(context.Background(), cl)
			Expect(adherence).To(Equal(configv1.TLSAdherencePolicyNoOpinion))
			Expect(profile.MinTLSVersion).To(Equal(tlspkg.DefaultMinTLSVersion))
			Expect(profile.Ciphers).To(Equal(tlspkg.DefaultTLSCiphers))
		})
	})

	It("returns custom groups from the APIServer", func() {
		groups := []configv1.TLSGroup{configv1.TLSGroupSecP384r1, configv1.TLSGroupSecP256r1}
		apiServer := &configv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: tlspkg.APIServerName},
			Spec: configv1.APIServerSpec{
				TLSSecurityProfile: &configv1.TLSSecurityProfile{
					Type: configv1.TLSProfileCustomType,
					Custom: &configv1.CustomTLSProfile{TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS12,
						Groups:        groups,
					}},
				},
				TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
			},
		}
		cl := fake.NewClientBuilder().WithScheme(operatorScheme).WithObjects(apiServer).Build()
		profile, adherence := fetchClusterTLSState(context.Background(), cl)
		Expect(adherence).To(Equal(configv1.TLSAdherencePolicyStrictAllComponents))
		Expect(profile.Groups).To(Equal(groups))
	})
})

var _ = Describe("applyClusterTLSProfile", func() {
	var baseConfig *tls.Config

	BeforeEach(func() {
		baseConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	})

	Context("when adherence is NoOpinion", func() {
		It("does not modify the config", func() {
			profile := *configv1.TLSProfiles[configv1.TLSProfileModernType]
			unsupported := applyClusterTLSProfile(baseConfig, profile, configv1.TLSAdherencePolicyNoOpinion)

			Expect(unsupported).To(BeNil())
			Expect(baseConfig.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
		})
	})

	Context("when adherence is LegacyAdheringComponentsOnly", func() {
		It("does not modify the config", func() {
			profile := *configv1.TLSProfiles[configv1.TLSProfileModernType]
			unsupported := applyClusterTLSProfile(baseConfig, profile, configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly)

			Expect(unsupported).To(BeNil())
			Expect(baseConfig.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
		})
	})

	Context("when adherence is StrictAllComponents", func() {
		It("applies the Modern profile (TLS 1.3)", func() {
			profile := *configv1.TLSProfiles[configv1.TLSProfileModernType]
			unsupported := applyClusterTLSProfile(baseConfig, profile, configv1.TLSAdherencePolicyStrictAllComponents)

			Expect(unsupported).To(BeEmpty())
			Expect(baseConfig.MinVersion).To(Equal(uint16(tls.VersionTLS13)))
		})

		It("applies the Intermediate profile (TLS 1.2)", func() {
			profile := *configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
			unsupported := applyClusterTLSProfile(baseConfig, profile, configv1.TLSAdherencePolicyStrictAllComponents)

			Expect(baseConfig.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
			Expect(baseConfig.CipherSuites).NotTo(BeEmpty())
			_ = unsupported
		})
	})
})

func TestApplyClusterTLSGroups(t *testing.T) {
	for name, tc := range map[string]struct {
		groups      []configv1.TLSGroup
		adherence   configv1.TLSAdherencePolicy
		wantCurves  []tls.CurveID
		unsupported []string
	}{
		"NIST groups exclude X25519 and preserve order": {
			groups: []configv1.TLSGroup{
				configv1.TLSGroupSecP384r1, configv1.TLSGroupSecP256r1, configv1.TLSGroupSecP521r1,
			},
			adherence:  configv1.TLSAdherencePolicyStrictAllComponents,
			wantCurves: []tls.CurveID{tls.CurveP384, tls.CurveP256, tls.CurveP521},
		},
		"classical and hybrid X25519 groups": {
			groups:     []configv1.TLSGroup{configv1.TLSGroupX25519, configv1.TLSGroupX25519MLKEM768},
			adherence:  configv1.TLSAdherencePolicyStrictAllComponents,
			wantCurves: []tls.CurveID{tls.X25519, tls.X25519MLKEM768},
		},
		"unsupported groups are skipped and returned": {
			groups:      []configv1.TLSGroup{"unknown-group", configv1.TLSGroupSecP256r1},
			adherence:   configv1.TLSAdherencePolicyStrictAllComponents,
			wantCurves:  []tls.CurveID{tls.CurveP256},
			unsupported: []string{"unknown-group"},
		},
		"all unsupported groups leave Go defaults": {
			groups:      []configv1.TLSGroup{"unknown-group"},
			adherence:   configv1.TLSAdherencePolicyStrictAllComponents,
			unsupported: []string{"unknown-group"},
		},
		"Go 1.26 hybrid groups are skipped": {
			groups: []configv1.TLSGroup{
				configv1.TLSGroupSecP256r1,
				configv1.TLSGroupSecP256r1MLKEM768,
				configv1.TLSGroupSecP384r1MLKEM1024,
			},
			adherence:  configv1.TLSAdherencePolicyStrictAllComponents,
			wantCurves: []tls.CurveID{tls.CurveP256},
			unsupported: []string{
				string(configv1.TLSGroupSecP256r1MLKEM768),
				string(configv1.TLSGroupSecP384r1MLKEM1024),
			},
		},
		"unset groups leave Go defaults": {
			adherence: configv1.TLSAdherencePolicyStrictAllComponents,
		},
		"empty groups leave Go defaults": {
			groups:    []configv1.TLSGroup{},
			adherence: configv1.TLSAdherencePolicyStrictAllComponents,
		},
		"no opinion ignores configured groups": {
			groups:    []configv1.TLSGroup{configv1.TLSGroupSecP521r1},
			adherence: configv1.TLSAdherencePolicyNoOpinion,
		},
		"legacy adherence ignores configured groups": {
			groups:    []configv1.TLSGroup{configv1.TLSGroupSecP521r1},
			adherence: configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly,
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := defaultServerTLSConfig()
			c.ClientAuth = tls.RequireAndVerifyClientCert
			c.ClientCAs = x509.NewCertPool()
			clientCAs := c.ClientCAs
			profile := configv1.TLSProfileSpec{
				MinTLSVersion: configv1.VersionTLS13,
				Groups:        tc.groups,
			}

			unsupported := applyClusterTLSProfile(c, profile, tc.adherence)
			require.Equal(t, tc.unsupported, unsupported)
			require.Equal(t, tc.wantCurves, c.CurvePreferences)
			require.Equal(t, tls.RequireAndVerifyClientCert, c.ClientAuth)
			require.Same(t, clientCAs, c.ClientCAs)
			require.Equal(t, []string{"http/1.1"}, c.NextProtos)
		})
	}
}
