package core_scan_e2e

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"testing"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var brokenContentImagePath string
var contentImagePath string

func TestMain(m *testing.M) {
	f := framework.NewFramework()
	err := f.SetUp()
	if err != nil {
		log.Fatal(err)
	}

	contentImagePath = os.Getenv("CONTENT_IMAGE")
	if contentImagePath == "" {
		fmt.Println("Please set the 'CONTENT_IMAGE' environment variable")
		os.Exit(1)
	}

	brokenContentImagePath = os.Getenv("BROKEN_CONTENT_IMAGE")

	if brokenContentImagePath == "" {
		fmt.Println("Please set the 'BROKEN_CONTENT_IMAGE' environment variable")
		os.Exit(1)
	}

	exitCode := m.Run()
	if exitCode == 0 || (exitCode > 0 && f.CleanUpOnError()) {
		if err = f.TearDown(); err != nil {
			log.Fatal(err)
		}
	}
	os.Exit(exitCode)
}

func TestSingleScanSucceeds(t *testing.T) {
	t.Parallel()
	f := framework.Global

	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatalf("failed to create scan %s: %s", scanName, err)
	}
	defer f.Client.Delete(context.TODO(), testScan)

	// Verify scanner container security capabilities during running phase
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}

	// Assert scanner container has correct capabilities (drops all, only has CAP_SYS_CHROOT)
	pods, err := f.GetPodsForScan(scanName)
	if err != nil {
		t.Fatal(err)
	}
	if len(pods) < 1 {
		t.Fatal("No scanner pods found for the scan")
	}

	// Find the scanner container and verify its capabilities
	found := false
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			if container.Name == "scanner" {
				found = true
				if container.SecurityContext == nil {
					t.Fatal("Scanner container has no security context")
				}
				if container.SecurityContext.Capabilities == nil {
					t.Fatal("Scanner container has no capabilities configuration")
				}

				// Verify privileged mode is false
				if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
					t.Fatal("Expected scanner container to run in non-privileged mode")
				}

				// Verify all capabilities are dropped
				droppedCaps := container.SecurityContext.Capabilities.Drop
				if len(droppedCaps) != 1 || string(droppedCaps[0]) != "ALL" {
					t.Fatalf("Expected scanner container to drop ALL capabilities, got: %v", droppedCaps)
				}

				// Verify CAP_SYS_CHROOT and CAP_SYS_ADMIN are added
				addedCaps := container.SecurityContext.Capabilities.Add
				if len(addedCaps) != 2 {
					t.Fatalf("Expected scanner container to have CAP_SYS_CHROOT and CAP_SYS_ADMIN capabilities, got: %v", addedCaps)
				}
				hasChroot := false
				hasSysAdmin := false
				for _, cap := range addedCaps {
					if string(cap) == "CAP_SYS_CHROOT" {
						hasChroot = true
					}
					if string(cap) == "CAP_SYS_ADMIN" {
						hasSysAdmin = true
					}
				}
				if !hasChroot || !hasSysAdmin {
					t.Fatalf("Expected scanner container to have both CAP_SYS_CHROOT and CAP_SYS_ADMIN capabilities, got: %v", addedCaps)
				}
				break
			}
		}
		if found {
			break
		}
	}

	if !found {
		t.Fatal("Scanner container not found in any pod")
	}

	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertScanIsCompliant(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	aggrString := fmt.Sprintf("compliance_operator_compliance_scan_status_total{name=\"%s\",phase=\"AGGREGATING\",result=\"NOT-AVAILABLE\"}", scanName)
	metricsSet := map[string]int{
		fmt.Sprintf("compliance_operator_compliance_scan_status_total{name=\"%s\",phase=\"DONE\",result=\"COMPLIANT\"}", scanName):          1,
		fmt.Sprintf("compliance_operator_compliance_scan_status_total{name=\"%s\",phase=\"LAUNCHING\",result=\"NOT-AVAILABLE\"}", scanName): 1,
		fmt.Sprintf("compliance_operator_compliance_scan_status_total{name=\"%s\",phase=\"PENDING\",result=\"\"}", scanName):                1,
		fmt.Sprintf("compliance_operator_compliance_scan_status_total{name=\"%s\",phase=\"RUNNING\",result=\"NOT-AVAILABLE\"}", scanName):   1,
	}

	var metErr error
	// Aggregating may be variable, could be registered 1 to 3 times.
	for i := 1; i < 4; i++ {
		metricsSet[aggrString] = i
		err = framework.AssertEachMetric(f.OperatorNamespace, metricsSet)
		if err == nil {
			metErr = nil
			break
		}
		metErr = err
	}

	if metErr != nil {
		t.Fatalf("failed to assert metrics for scan %s: %s\n", scanName, metErr)
	}

	err = f.AssertScanHasValidPVCReference(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatalf("failed to assert PVC reference for scan %s: %s", scanName, err)
	}

	// Validate exit-code is "0"
	exitCode, _, err := f.GetScanExitCodeAndErrorMsg(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
	expectedExitCode := "0"
	if exitCode != expectedExitCode {
		t.Fatalf("Expected ConfigMap exit-code to be '%s', but got: '%s'", expectedExitCode, exitCode)
	}
}

func TestSingleScanTimestamps(t *testing.T) {
	t.Parallel()
	f := framework.Global

	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatalf("failed to create scan %s: %s", scanName, err)
	}
	defer f.Client.Delete(context.TODO(), testScan)

	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	// assertComplianceCheckResultTimestamps checks that the timestamps are set
	// and that they are set to the same value of startTimestamp of the scan
	err = f.AssertComplianceCheckResultTimestamps(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	// rerun the scan
	err = f.ReRunScan(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	// assertComplianceCheckResultTimestamps checks that the timestamps are set
	// and that they are set to the same value of startTimestamp of the scan
	err = f.AssertComplianceCheckResultTimestamps(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

}

