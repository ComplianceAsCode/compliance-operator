package e2e

import (
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestE2e(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "E2e Suite")
}

var _ = BeforeSuite(func() {
	ensureOperator()

	By("Switching context to compliance-operator NS")
	oc("project", "openshift-compliance")
	copods := oc("get", "deployments", "-l", "name=compliance-operator")
	if strings.Contains(copods, "No resources found") {
		time.Sleep(30 * time.Second)
	}

	By("Getting install plans")
	ipraw := oc("get", "installplans", "-o", `jsonpath={range .items[:]}{.metadata.name}{"\n"}{end}`)
	ips := strings.Split(ipraw, "\n")

	// NOTE(jaosorior): If there is more than one install plan
	// one of them will fail... this might be a bug in the OLM
	// Let's delete them and wait for the reconcile to create
	// one again.
	if len(ips) > 1 {
		By("Race in install plans... re-installing")
		oc("delete", "installplans", "--all")
		oc("delete", "csv", "--all")
		oc("delete", "subscriptions.operators", "--all")
		time.Sleep(30 * time.Second)

		ensureOperator()
		time.Sleep(30 * time.Minute)

		ipraw = oc("get", "installplans", "-o", `jsonpath={range .items[:]}{.metadata.name}{"\n"}{end}`)
		ips = strings.Split(ipraw, "\n")
	}

	By("Waiting for install plan")
	for _, ip := range ips {
		ocWaitFor("condition=installed", "installplan", ip)
	}

	By("Waiting for Compliance Operator")

	ocWaitFor("condition=available", "deployment", "compliance-operator")
	pbs := oc("get", "profilebundles")
	if strings.Contains(pbs, "No resources found") {
		time.Sleep(90 * time.Second)
	}

	By("Waiting for ProfileBundles")
	ocWaitLongFor("condition=ready", "profilebundle", "ocp4")
	ocWaitLongFor("condition=ready", "profilebundle", "rhcos4")
})

var _ = AfterSuite(func() {
})
