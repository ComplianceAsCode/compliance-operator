package e2e

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func verifyOCControls(p string) string {
	out := oc("compliance", "controls", "profile", p)
	Expect(out).To(MatchRegexp(`.*NIST-800-53.*[A-Z]+-[0-9]+`))
	return out
}

var _ = Describe("controls", func() {
	When("getting controls for", func() {
		It("E8 profile", func() {
			verifyOCControls("rhcos4-e8")
		})
		It("CIS profile", func() {
			out := verifyOCControls("ocp4-cis")
			Expect(out).To(MatchRegexp(`.*CIS.*[0-9]+\.[0-9]+\.[0-9]+`))
		})
	})
})
