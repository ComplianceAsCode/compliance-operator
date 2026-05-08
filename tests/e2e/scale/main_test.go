package scale_e2e

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
)

func TestMain(m *testing.M) {
	f := framework.NewFramework()
	err := f.SetUp()
	if err != nil {
		log.Fatal(err)
	}

	exitCode := m.Run()
	if exitCode == 0 || (exitCode > 0 && f.CleanUpOnError()) {
		if err = f.TearDown(); err != nil {
			log.Fatal(err)
		}
	}
	os.Exit(exitCode)
}

func TestPCIDSSApiChecksWithLargeMachineConfigScale(t *testing.T) {
	f := framework.Global
	const (
		mcCount  = 150
		mcPrefix = "e2e-stress-mc-"
		// Each MC carries ~10KB of systemd unit data that survives
		// the filterMcList stripping in cmd/manager/scap.go.
		unitPaddingSize    = 10 * 1024
		minTotalPostFilter = 500 * 1024
	)

	suiteName := "pci-dss-stress-test"
	scanSettingName := "stress-test-setting"
	poolName := framework.TestPoolName

	log.Printf("Creating %d MachineConfigs with ~%dKB systemd unit data each\n", mcCount, unitPaddingSize/1024)
	mcList := make([]*mcfgv1.MachineConfig, mcCount)

	errChan := make(chan error, mcCount)

	for i := 0; i < mcCount; i++ {
		padding := strings.Repeat("A", unitPaddingSize)
		mcList[i] = &mcfgv1.MachineConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("%s%d", mcPrefix, i),
				Labels: map[string]string{
					"machineconfiguration.openshift.io/role": poolName,
				},
			},
			Spec: mcfgv1.MachineConfigSpec{
				Config: k8sruntime.RawExtension{
					Raw: []byte(fmt.Sprintf(`{
						"ignition": {"version": "3.2.0"},
						"systemd": {
							"units": [{
								"name": "e2e-stress-%d.service",
								"enabled": false,
								"contents": "[Unit]\nDescription=e2e stress test unit %d padding=%s\n[Service]\nType=oneshot\nExecStart=/bin/true\n"
							}]
						}
					}`, i, i, padding)),
				},
			},
		}

		go func(mc *mcfgv1.MachineConfig) {
			if err := f.Client.Create(context.TODO(), mc, nil); err != nil {
				errChan <- fmt.Errorf("failed to create MachineConfig %s: %w", mc.Name, err)
			} else {
				errChan <- nil
			}
		}(mcList[i])
	}

	var failCount int
	var lastErr error
	for i := 0; i < mcCount; i++ {
		if err := <-errChan; err != nil {
			failCount++
			lastErr = err
		}
	}
	if failCount > 0 {
		t.Fatalf("%d/%d MachineConfigs failed to create, last error: %s", failCount, mcCount, lastErr)
	}
	log.Printf("Successfully created %d MachineConfigs\n", mcCount)

	defer func() {
		log.Printf("Cleaning up %d MachineConfigs\n", mcCount)
		for _, mc := range mcList {
			if err := f.Client.Delete(context.TODO(), mc); err != nil && !apierrors.IsNotFound(err) {
				log.Printf("WARNING: failed to delete MachineConfig %s: %s", mc.Name, err)
			}
		}

		log.Printf("Waiting for MachineConfigPool %s to stabilize after MC deletion\n", poolName)
		err := wait.PollImmediate(framework.RetryInterval, 10*time.Minute, func() (bool, error) {
			pool := &mcfgv1.MachineConfigPool{}
			if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: poolName}, pool); err != nil {
				if apierrors.IsNotFound(err) {
					return true, nil
				}
				return false, err
			}

			for _, c := range pool.Status.Conditions {
				if c.Type == mcfgv1.MachineConfigPoolUpdated && c.Status == corev1.ConditionTrue {
					log.Printf("MachineConfigPool %s is stable after cleanup\n", poolName)
					return true, nil
				}
			}
			return false, nil
		})
		if err != nil {
			log.Printf("WARNING: MachineConfigPool failed to stabilize after cleanup: %s\n", err)
		}
	}()

	// Validate total data volume that will survive filterMcList.
	// filterMcList (cmd/manager/scap.go) strips Storage.Files but preserves Systemd.Units.
	var totalRawBytes int
	fetchedMCList := &mcfgv1.MachineConfigList{}
	if err := f.Client.List(context.TODO(), fetchedMCList, client.MatchingLabels{
		"machineconfiguration.openshift.io/role": poolName,
	}); err != nil {
		t.Fatalf("failed to list MachineConfigs: %s", err)
	}
	for _, mc := range fetchedMCList.Items {
		if strings.HasPrefix(mc.Name, mcPrefix) {
			totalRawBytes += len(mc.Spec.Config.Raw)
		}
	}
	log.Printf("Total post-filter MachineConfig data: %d bytes (~%dKB) across %d MCs\n",
		totalRawBytes, totalRawBytes/1024, mcCount)
	if totalRawBytes < minTotalPostFilter {
		t.Fatalf("Total MC data %d bytes is below minimum threshold %d bytes - test would not stress api-resource-collector",
			totalRawBytes, minTotalPostFilter)
	}

	// The MCO renders all MachineConfigs targeting this pool into a single rendered
	// config and rolls it out to pool nodes as one update.
	log.Printf("Waiting for MachineConfigPool %s to process the MachineConfigs\n", poolName)
	err := wait.PollImmediate(framework.RetryInterval, 10*time.Minute, func() (bool, error) {
		pool := &mcfgv1.MachineConfigPool{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: poolName}, pool); err != nil {
			return false, err
		}

		for _, c := range pool.Status.Conditions {
			if c.Type == mcfgv1.MachineConfigPoolUpdated && c.Status == corev1.ConditionTrue {
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("MachineConfigPool failed to update: %s", err)
	}

	log.Printf("Creating ScanSetting %s\n", scanSettingName)
	scanSetting := &compv1alpha1.ScanSetting{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingName,
			Namespace: f.OperatorNamespace,
		},
		ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
			AutoApplyRemediations: false,
		},
		ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
			Debug: true,
		},
		Roles: []string{poolName},
	}
	err = f.Client.Create(context.TODO(), scanSetting, nil)
	if err != nil {
		t.Fatalf("failed to create ScanSetting: %s", err)
	}
	defer f.Client.Delete(context.TODO(), scanSetting)

	log.Printf("Creating ScanSettingBinding %s with PCI-DSS profiles\n", suiteName)
	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     "ocp4-pci-dss-node",
				Kind:     "Profile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
			{
				Name:     "ocp4-pci-dss",
				Kind:     "Profile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			Name:     scanSetting.Name,
			Kind:     "ScanSetting",
			APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}
	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatalf("failed to create ScanSettingBinding: %s", err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	log.Printf("Waiting for ComplianceSuite %s to complete (this validates api-checks pod stability)\n", suiteName)
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatalf("Suite did not reach DONE state: %s", err)
	}

	suite := &compv1alpha1.ComplianceSuite{}
	suiteKey := types.NamespacedName{Name: suiteName, Namespace: f.OperatorNamespace}
	if err := f.Client.Get(context.TODO(), suiteKey, suite); err != nil {
		t.Fatalf("failed to get ComplianceSuite: %s", err)
	}

	for _, scanWrapper := range suite.Spec.Scans {
		pods, err := f.GetPodsForScan(scanWrapper.Name)
		if err != nil {
			t.Fatalf("failed to get pods for scan %s: %s", scanWrapper.Name, err)
		}

		for _, pod := range pods {
			for _, containerStatus := range pod.Status.ContainerStatuses {
				if containerStatus.State.Waiting != nil &&
					containerStatus.State.Waiting.Reason == "CrashLoopBackOff" {
					t.Fatalf("Pod %s container %s is in CrashLoopBackOff state",
						pod.Name, containerStatus.Name)
				}
			}
		}
	}

	log.Printf("Test completed successfully - PCI-DSS api-checks pods handled %d MachineConfigs (%dKB post-filter data) without crashing\n",
		mcCount, totalRawBytes/1024)
}
