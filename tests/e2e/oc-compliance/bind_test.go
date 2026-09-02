package e2e

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("bind", func() {

	When("using a pre-determined name", func() {
		const ssbName = "bind-test-fixed-name-ssb"
		AfterEach(func() {
			if !CurrentGinkgoTestDescription().Failed {
				By("deleting ScanSettingBindings created by this test")
				oc("delete", "scansettingbinding", ssbName)
				time.Sleep(defaultSleep)
			}
		})

		It("Successfully creates a ScanSettingBinding", func() {
			oc("compliance", "bind", "--name", ssbName, "profile/ocp4-cis")
			time.Sleep(defaultSleep)
			ocWaitFor("condition=ready", "scansettingbinding", ssbName)
		})
	})

	When("using --dry-run", func() {
		It("Successfully creates a ScanSettingBinding", func() {
			ssb := oc("compliance", "bind", "--dry-run", "--name", "test", "profile/ocp4-cis")
			Expect(ssb).Should(MatchRegexp(`.*\n\s+name: test\n.*`))
			Expect(ssb).Should(MatchRegexp(`.*\n\s+kind: Profile\n\s+name: ocp4-cis\n.*`))
		})
	})
})
