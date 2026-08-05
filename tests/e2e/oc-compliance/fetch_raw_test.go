package e2e

import (
	"fmt"
	"os"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("fetch-raw", func() {
	Context("With a pre-existing profile being scanned", func() {
		var dir string

		BeforeEach(func() {
			withCISScan("fetch-raw-scan")
			var tmpErr error
			dir, tmpErr = os.MkdirTemp("", "oc-compliance-fetch-raw")
			By(fmt.Sprintf("Created temporary directory for this test: %s", dir))
			Expect(tmpErr).ShouldNot(HaveOccurred())
		}, float64(scanDoneTimeout))

		AfterEach(func() {
			if !CurrentGinkgoTestDescription().Failed {
				By(fmt.Sprintf("Removing temporary directory for this test: %s", dir))
				os.RemoveAll(dir)
			}
		})

		assertFilesOutput := func(dirs []string) {
			By("Assert we got results")
			Expect(len(dirs)).Should(BeNumerically(">", 0))
			for _, dir := range dirs {
				Expect(dir).ToNot(BeEmpty())
			}
		}

		assertFetchRawWorks := func(objtype, objname, wdir string) {
			By("Calling oc compliance fetch-raw")
			oc("compliance", "fetch-raw", objtype, objname, "-o", wdir)

			By("Getting items from scan")
			dirraw := do("find", wdir, "-name", "*.xml.bzip2")
			dirs := strings.Split(dirraw, "\n")
			assertFilesOutput(dirs)
		}

		assertFetchRawWithHTMLWorks := func(objtype, objname, wdir string) {
			skipIfError("which", "oscap")
			By("Calling oc compliance fetch-raw with --html flag")
			oc("compliance", "fetch-raw", "--html", objtype, objname, "-o", wdir)

			By("Getting HTML files from scan")
			dirraw := do("find", wdir, "-name", "*.html")
			dirs := strings.Split(dirraw, "\n")
			assertFilesOutput(dirs)
		}

		When("using ScanSettingBinding", func() {
			It("Fetches the results to the appropriate directory", func() {
				assertFetchRawWorks("scansettingbinding", "fetch-raw-scan", dir)
			})

			It("Fetches the HTML results to the appropriate directory", func() {
				assertFetchRawWithHTMLWorks("scansettingbinding", "fetch-raw-scan", dir)
			})
		})

		When("using ComplianceSuite", func() {
			It("Fetches the results to the appropriate directory", func() {
				assertFetchRawWorks("compliancesuite", "fetch-raw-scan", dir)
			})

			It("Fetches the HTML results to the appropriate directory", func() {
				assertFetchRawWithHTMLWorks("compliancesuite", "fetch-raw-scan", dir)
			})
		})

		When("using ComplianceScan", func() {
			It("Fetches the results to the appropriate directory", func() {
				assertFetchRawWorks("compliancescan", "ocp4-cis", dir)
			})

			It("Fetches the HTML results to the appropriate directory", func() {
				assertFetchRawWithHTMLWorks("compliancescan", "ocp4-cis", dir)
			})
		})

	})
})
