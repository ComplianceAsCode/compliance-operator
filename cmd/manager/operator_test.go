package manager

import (
	"reflect"
	"runtime"
	"strings"

	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/metrics"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Operator Startup Function tests", func() {
	Context("Operator log format", func() {
		It("logs in the ISO8601TimeEncoder human-readable format", func() {
			encoder := operatorTimeEncoder()
			fullFunctionName := runtime.FuncForPC(reflect.ValueOf(encoder).Pointer()).Name()
			splitFunctionName := strings.Split(fullFunctionName, ".")
			Expect(len(splitFunctionName)).To(BeEquivalentTo(4))
			Expect(splitFunctionName[len(splitFunctionName)-1]).To(BeEquivalentTo("ISO8601TimeEncoder"))
		})
	})
	Context("Service Monitor Creation", func() {
		When("Installing to non-controlled namespace", func() {
			It("ServiceMonitor is generated with the proper TLSConfig ServerName", func() {
				metricService := operatorMetricService("foobar")
				sm := generateOperatorServiceMonitor(metricService, "foobar", "secret")
				controllerMetricServiceFound := false
				expectedServerName := "metrics.foobar.svc"
				for _, ep := range sm.Spec.Endpoints {
					if ep.Port == metrics.ControllerMetricsServiceName && ep.TLSConfig != nil {
						Expect(ep.TLSConfig.ServerName).To(BeEquivalentTo(&expectedServerName))
						controllerMetricServiceFound = true
					}
				}
				Expect(controllerMetricServiceFound).To(BeTrue())
			})
		})
	})
})
