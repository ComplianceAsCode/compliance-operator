package e2e

import (
	"fmt"
	"os"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("fetch-stig-results", func() {
	Context("With a STIG profile being scanned", func() {
		var dir string

		BeforeEach(func() {
			withScan("fetch-stig-scan", "stig")
			var tmpErr error
			dir, tmpErr = os.MkdirTemp("", "oc-compliance-fetch-stig-results")
			By(fmt.Sprintf("Created temporary directory for this test: %s", dir))
			Expect(tmpErr).ShouldNot(HaveOccurred())
		}, float64(scanDoneTimeout))

		AfterEach(func() {
			if !CurrentGinkgoTestDescription().Failed {
				By(fmt.Sprintf("Removing temporary directory for this test: %s", dir))
				os.RemoveAll(dir)
			}
		})

		It("Writes a single combined XCCDF file by default", func() {
			By("Calling oc compliance fetch-stig-results")
			oc("compliance", "fetch-stig-results", "fetch-stig-scan", "-o", dir)

			By("Asserting a single combined file named after the binding was written")
			filesRaw := do("find", dir, "-name", "*.xml")
			files := strings.Split(strings.TrimSpace(filesRaw), "\n")
			Expect(files).To(HaveLen(1))
			Expect(files[0]).To(HaveSuffix("fetch-stig-scan.xml"))

			By("Asserting the file has STIG rule results")
			content := do("cat", fmt.Sprintf("%s/fetch-stig-scan.xml", dir))
			Expect(content).To(ContainSubstring(`<rule-result idref="SV-`))
			Expect(content).To(MatchRegexp(`<result>(pass|fail|notchecked|error|notapplicable|unknown|informational)</result>`))
		})

		It("Writes one file per scan with --per-scan", func() {
			By("Calling oc compliance fetch-stig-results with --per-scan")
			oc("compliance", "fetch-stig-results", "fetch-stig-scan", "--per-scan", "-o", dir)

			By("Asserting multiple per-scan files were written")
			filesRaw := do("find", dir, "-name", "*.xml")
			files := strings.Split(strings.TrimSpace(filesRaw), "\n")
			Expect(len(files)).Should(BeNumerically(">", 1))

			By("Asserting the platform scan file has STIG rule results")
			content := do("cat", fmt.Sprintf("%s/ocp4-stig.xml", dir))
			Expect(content).To(ContainSubstring(`<rule-result idref="SV-`))
		})

		It("Writes a single file when --scan is given", func() {
			By("Calling oc compliance fetch-stig-results with --scan")
			oc("compliance", "fetch-stig-results", "fetch-stig-scan", "--scan", "ocp4-stig", "-o", dir)

			By("Asserting only the requested scan file was written")
			filesRaw := do("find", dir, "-name", "*.xml")
			files := strings.Split(strings.TrimSpace(filesRaw), "\n")
			Expect(files).To(HaveLen(1))
			Expect(files[0]).To(HaveSuffix("ocp4-stig.xml"))

			By("Asserting the file has STIG rule results")
			content := do("cat", fmt.Sprintf("%s/ocp4-stig.xml", dir))
			Expect(content).To(ContainSubstring(`<rule-result idref="SV-`))
		})
	})
})
