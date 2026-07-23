package manager

import (
	"crypto/tls"

	configv1 "github.com/openshift/api/config/v1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

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
