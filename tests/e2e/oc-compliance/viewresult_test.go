package e2e

import (
	"math/rand"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("viewresult", func() {
	var targetResult string
	BeforeEach(func() {
		// Ensure there's some results in there
		withCISScan("viewresult-scan")
		results := oc("get", "compliancecheckresults",
			"-o", `jsonpath={range .items[:]}{.metadata.name}{"\n"}{end}`)
		resSlice := strings.Split(results, "\n")
		idx := rand.Intn(len(resSlice))
		targetResult = resSlice[idx]
	}, float64(scanDoneTimeout))

	It("gets relevant info for result", func() {
		out := oc("compliance", "view-result", targetResult)
		Expect(out).To(MatchRegexp(`Status.*`))
		Expect(out).To(MatchRegexp(`Severity.*`))
		Expect(out).To(MatchRegexp(`Description.*`))
		Expect(out).To(MatchRegexp(`Controls.*`))
		Expect(out).To(MatchRegexp(`Available Fix.*`))
		Expect(out).To(MatchRegexp(`Remediation Created.*`))
	})
})
