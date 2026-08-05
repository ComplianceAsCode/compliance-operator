package e2e

import (
	"fmt"
	"math/rand"
	"os"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func assertFetchFixesFetchedSomething(dir string) {
	By("Finding remediations")
	dirraw := do("find", dir, "-name", "*.yaml")
	dirs := strings.Split(dirraw, "\n")

	By("Assert we got results")
	Expect(len(dirs)).Should(BeNumerically(">", 0))
}

var _ = Describe("fetch-fixes", func() {
	var dir string
	BeforeEach(func() {
		var tmpErr error
		dir, tmpErr = os.MkdirTemp("", "fetch-fixes")
		Expect(tmpErr).ShouldNot(HaveOccurred())
		By(fmt.Sprintf("Created temporary directory for this test: %s", dir))
	})
	Context("With a remediation", func() {
		var targetRem string

		BeforeEach(func() {
			withCISScan("fetch-fixes-scan")
			rems := oc("get", "complianceremediations",
				"-o", `jsonpath={range .items[:]}{.metadata.name}{"\n"}{end}`)
			remsSlice := strings.Split(rems, "\n")
			idx := rand.Intn(len(remsSlice))
			targetRem = remsSlice[idx]
		}, float64(scanDoneTimeout))

		It("fetches fixes for ComplianceRemediation", func() {
			oc("compliance", "fetch-fixes", "complianceremediation", targetRem, "-o", dir)
			assertFetchFixesFetchedSomething(dir)
		})
	})

	Context("With an MC remediation", func() {
		It("fetches fixes for rule", func() {
			oc("compliance", "fetch-fixes", "rule", "rhcos4-coreos-pti-kernel-argument", "-o", dir)
			assertFetchFixesFetchedSomething(dir)
			name := do("grep", "-R", "name:.*75.*worker", dir)
			Expect(name).ToNot(BeEmpty())
			label := do("grep", "-R", "machineconfiguration.openshift.io/role: master", dir)
			Expect(label).ToNot(BeEmpty())
		})
	})

	Context("With parsed content", func() {
		It("fetches fixes for profile", func() {
			oc("compliance", "fetch-fixes", "profile", "ocp4-cis", "-o", dir)
		})
	})
})
