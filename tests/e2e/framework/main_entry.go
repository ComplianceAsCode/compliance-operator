package framework

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/go-logr/logr"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func NewFramework() *Framework {
	fopts := &frameworkOpts{}
	fopts.addToFlagSet(flag.CommandLine)

	kcFlag := flag.Lookup(KubeConfigFlag)
	if kcFlag == nil {
		flag.StringVar(&fopts.kubeconfigPath, KubeConfigFlag, "", "path to kubeconfig")
	}

	flag.Parse()

	if kcFlag != nil {
		fopts.kubeconfigPath = kcFlag.Value.String()
	}

	f, err := newFramework(fopts)
	if err != nil {
		log.Fatalf("Failed to create framework: %v", err)
	}
	Global = f

	// This is required because controller-runtime expects its consumers to
	// set a logger through log.SetLogger within 30 seconds of the program's
	// initalization. If not set, the entire debug stack is printed as an
	// error, see: https://github.com/kubernetes-sigs/controller-runtime/blob/ed8be90/pkg/log/log.go#L59
	// Since we have our own logging and don't care about controller-runtime's
	// logger, we configure it's logger to do nothing.
	ctrllog.SetLogger(logr.New(ctrllog.NullLogSink{}))

	return f
}

func (f *Framework) CleanUpOnError() bool {
	return f.cleanupOnError
}

func (f *Framework) SetUp() error {
	log.Printf("switching to %s directory to setup and execute tests", f.projectRoot)
	err := os.Chdir(f.projectRoot)
	if err != nil {
		return fmt.Errorf("failed to change directory to project root: %w", err)
	}

	err = f.ensureTestNamespaceExists()
	if err != nil {
		return fmt.Errorf("unable to create or use namespace %s for testing: %w", f.OperatorNamespace, err)
	}

	log.Printf("creating cluster resources in %s", f.globalManPath)
	err = f.createFromYAMLFile(&f.globalManPath)
	if err != nil {
		return fmt.Errorf("failed to setup test resources: %w", err)
	}

	err = f.addFrameworks()
	if err != nil {
		return err
	}

	err = f.replaceNamespaceFromManifest()
	if err != nil {
		return err
	}

	log.Printf("creating namespaced resources in %s", *f.NamespacedManPath)
	err = f.createFromYAMLFile(f.NamespacedManPath)
	if err != nil {
		return fmt.Errorf("failed to setup test resources: %w", err)
	}

	err = f.initializeMetricsTestResources()
	if err != nil {
		return fmt.Errorf("failed to initialize cluster resources for metrics: %v", err)
	}

	retryInterval := time.Second * 5
	timeout := time.Minute * 30
	err = f.WaitForDeployment("compliance-operator", 1, retryInterval, timeout)
	if err != nil {
		return fmt.Errorf("timed out waiting for deployment to become available: %w", err)
	}

	err = f.WaitForProfileBundleStatus("rhcos4", compv1alpha1.DataStreamValid)
	if err != nil {
		return err
	}
	err = f.WaitForProfileBundleStatus("ocp4", compv1alpha1.DataStreamValid)
	if err != nil {
		return err
	}

	err = f.updateScanSettingsForDebug()
	if err != nil {
		return fmt.Errorf("failed to set scan setting bindings to debug: %w", err)
	}

	err = f.ensureE2EScanSettings()
	if err != nil {
		return fmt.Errorf("failed to configure scan settings for tests: %w", err)
	}

	err = f.createMachineConfigPool("e2e")
	if err != nil {
		return fmt.Errorf("failed to create Machine Config Pool %s: %w", "e2e", err)
	}
	err = f.createInvalidMachineConfigPool("e2e-invalid")
	if err != nil {
		return fmt.Errorf("failed to create Machine Config Pool %s: %w", "e2e-invalid", err)
		// log.Printf("failed to create Machine Config Pool %s: %s", "e2e-invalid", err)
		// log.Printf("continuing without invalid MachineConfigPool (cluster may have ValidatingAdmissionPolicy)")
	}

	return nil
}

// tearDown performs any tasks necessary to cleanup resources leftover from testing
// and assumes a specific order. All namespaced resources must be cleaned up before
// deleting the cluster-wide resources, like roles, service accounts, or the deployment.
// If we don't properly cleanup resources before deleting CRDs, it leaves resources in a
// terminating state, making them harder to cleanup.
func (f *Framework) TearDown() error {
	// Make sure all scans are cleaned up before we delete the CRDs. Scans should be cleaned up
	// because they're owned by ScanSettingBindings or ScanSuites, which should be cleaned up
	// by each individual test either directly or through deferred cleanup. If the test fails
	// because there are scans that haven't been cleaned up, we could have a bug in the
	// tests.
	err := f.waitForScanCleanup()
	if err != nil {
		return err
	}

	log.Printf("cleaning up Profile Bundles")
	err = f.cleanUpProfileBundle("rhcos4")
	if err != nil {
		return fmt.Errorf("failed to cleanup rhcos4 profile bundle: %w", err)
	}
	err = f.cleanUpProfileBundle("ocp4")
	if err != nil {
		return fmt.Errorf("failed to cleanup ocp4 profile bundle: %w", err)
	}

	err = f.deleteScanSettings("e2e-default")
	if err != nil {
		return err
	}
	err = f.deleteScanSettings("e2e-default-auto-apply")
	if err != nil {
		return err
	}

	// unlabel nodes
	err = f.restoreNodeLabelsForPool("e2e")
	if err != nil {
		return err
	}
	err = f.cleanUpMachineConfigPool("e2e")
	if err != nil {
		return err
	}
	// e2e-invalid mcp
	err = f.cleanUpMachineConfigPool("e2e-invalid")
	if err != nil {
		return err
	}

	// Clean up these resources explicitly in this method because it's guaranteed to run
	// after all the tests execute. It's also safer to clean up resources that require
	// a specific cleanup order explicitly than to rely on Go's defer function. Defer
	// is implemented as a stack, and doesn't guarantee safety across go routines
	// (which may be the case with parallel tests), making it possible for some
	// resources to get cleaned up before others. We don't want that to happen with
	// cluster resources like CRDs, because it will orphan custom resource instances
	// that haven't been cleaned up, yet.
	log.Printf("cleaning up namespaced resources in %s\n", f.OperatorNamespace)
	err = f.cleanUpFromYAMLFile(f.NamespacedManPath)
	if err != nil {
		return err
	}

	log.Println("cleaning up cluster resources")
	err = f.cleanUpFromYAMLFile(&f.globalManPath)
	if err != nil {
		return err
	}

	log.Printf("cleaning up namespace %s\n", f.OperatorNamespace)
	err = f.KubeClient.CoreV1().Namespaces().Delete(context.TODO(), f.OperatorNamespace, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to cleanup namespace %s: %w", f.OperatorNamespace, err)
	}
	return nil
}
