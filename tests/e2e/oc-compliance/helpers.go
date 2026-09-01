package e2e

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const defaultOCWaitTimeout = "--timeout=90s"
const defaultOCLongWaitTimeout = "--timeout=10m"
const scanDoneTimeout = 5 * time.Minute
const defaultSleep = 5 * time.Second

func ensureOperator() {
	By("Deploying the Compliance Operator")
	ocApplyFromString(`---
apiVersion: v1
kind: Namespace
metadata:
  name: openshift-compliance
`)

	ocApplyFromString(`---
apiVersion: operators.coreos.com/v1alpha1
kind: CatalogSource
metadata:
  name: compliance-operator
  namespace: openshift-marketplace
spec:
  displayName: Compliance Operator Upstream
  publisher: github.com/openshift/compliance-operator
  sourceType: grpc
  image: quay.io/compliance-operator/compliance-operator-catalog:latest
`)

	ocApplyFromString(`---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: compliance-operator-sub
  namespace: openshift-compliance
spec:
  channel: alpha
  name: compliance-operator
  source: compliance-operator
  sourceNamespace: openshift-marketplace
`)

	ocApplyFromString(`---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: compliance-operator
  namespace: openshift-compliance
spec:
  targetNamespaces:
  - openshift-compliance
`)
}

func do(cmd string, args ...string) string {
	execcmd := exec.Command(cmd, args...)
	output, err := execcmd.CombinedOutput()
	Expect(err).ShouldNot(HaveOccurred(),
		"The command '%s' shouldn't fail.\n- Arguments: %v\n- Output: %s", cmd, args, output)
	return strings.Trim(string(output), "\n")
}

func skipIfError(cmd string, args ...string) string {
	execcmd := exec.Command(cmd, args...)
	output, _ := execcmd.CombinedOutput()
	Skip(fmt.Sprintf("The command '%s' shouldn't fail. SKIPPING.\n- Arguments: %v\n- Output: %s", cmd, args, output))
	return strings.Trim(string(output), "\n")
}

func oc(args ...string) string {
	return do("oc", args...)
}

func ocApplyFromString(obj string) string {
	tmpfile, err := os.CreateTemp("", "oc-create")
	Expect(err).ShouldNot(HaveOccurred(), "Creating a temp file shouldn't fail")
	defer os.Remove(tmpfile.Name())
	defer tmpfile.Close()
	_, writeErr := io.WriteString(tmpfile, obj)
	Expect(writeErr).ShouldNot(HaveOccurred(), "Writing kube object to temp file shouldn't fail")
	return oc("apply", "-f", tmpfile.Name())
}

func ocApplyFromStringf(obj string, args ...interface{}) string {
	formatted := fmt.Sprintf(obj, args...)
	return ocApplyFromString(formatted)
}

func ocWaitFor(args ...string) string {
	return oc(append([]string{"wait", defaultOCWaitTimeout, "--for"}, args...)...)
}

func ocWaitLongFor(args ...string) string {
	return oc(append([]string{"wait", defaultOCLongWaitTimeout, "--for"}, args...)...)
}

func withScan(scan, profile string) {
	By("Creating a ScanSettingBinding for this test")
	ocApplyFromStringf(`---
apiVersion: compliance.openshift.io/v1alpha1
kind: ScanSettingBinding
metadata:
  name: %s
profiles:
- apiGroup: compliance.openshift.io/v1alpha1
  kind: Profile
  name: ocp4-%s
settingsRef:
  apiGroup: compliance.openshift.io/v1alpha1
  kind: ScanSetting
  name: default
`, scan, profile)

	time.Sleep(defaultSleep)
	ocWaitFor("condition=ready", "scansettingbinding", scan)

	By("Waiting for scan to be ready")
	ocWaitLongFor("condition=ready", "compliancesuite", scan)
}

// Will set up a scan with the given name and wait for it to be done.
// The scan will be done for the CIS benchmark.
func withCISScan(scan string) {
	withScan(scan, "cis")
}

func withE8Scan(scan string) {
	withScan(scan, "e8")
}
