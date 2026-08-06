package e2e

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"time"
)

const (
	reRunTimeout = 10 * time.Second
)

var _ = Describe("rerun-now", func() {
	Context("With a pre-existing profile being scanned", func() {
		BeforeEach(func() {
			withE8Scan("rerun-now-scan")
		}, float64(scanDoneTimeout))

		It("Re-reruns the scan", func() {
			By("checking that scan is done")
			phase := oc("get", "compliancesuite", "rerun-now-scan", "-o", `jsonpath={.status.phase}`)
			Expect(phase).Should(ContainSubstring("DONE"))

			By("doing oc compliance rerun-now")
			oc("compliance", "rerun-now", "scansettingbinding", "rerun-now-scan")

			By("checking the scan is re-kicked")
			Eventually(func() string {
				return oc("get", "compliancesuite", "rerun-now-scan", "-o", `jsonpath={.status.phase}`)
			}, reRunTimeout).Should(BeElementOf([]string{"PENDING", "LAUNCHING", "RUNNING"}))

			By("waiting for scan to be done")
			ocWaitLongFor("condition=ready", "compliancesuite", "rerun-now-scan")
		})
	})
})
