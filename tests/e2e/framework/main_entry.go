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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func NewFramework(opts ...Option) *Framework {
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
	for _, opt := range opts {
		opt(f)
	}
	f.scanPhase = newScanPhase()
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

	// Start streaming pod logs to $ARTIFACT_DIR as early as possible so that
	// short-lived scan pods are captured before the operator reaps them. No-op
	// when ARTIFACT_DIR is unset (local runs).
	f.stopPodLogs = f.StartPodLogCollector()

	log.Printf("creating cluster resources in %s", f.globalManPath)
	err = f.createFromYAMLFile(&f.globalManPath)
	if err != nil {
		return fmt.Errorf("failed to setup test resources: %w", err)
	}

	err = f.addFrameworks()
	if err != nil {
		return err
	}

	// Start creating the MachineConfigPool lanes now, if the suite asked for
	// them (WithTestPools). MCO takes about 30s to roll a node into each new
	// pool and that doesn't depend on the operator, so it overlaps with the
	// operator deployment and ProfileBundle parsing below. finishTestPools
	// joins it once the operator is up. See testpools.go.
	if f.useTestPools && os.Getenv("SKIP_MCP_SETUP") == "" {
		if err := f.startTestPools(); err != nil {
			return fmt.Errorf("failed to set up test pools: %w", err)
		}
	}

	err = f.replaceNamespaceFromManifest()
	if err != nil {
		return err
	}

	if f.useTestPools {
		f.pinOperatorToMasters, err = f.shouldPinOperatorToMasters()
		if err != nil {
			return err
		}
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

	err = f.waitForDefaultProfileBundles()
	if err != nil {
		return err
	}

	if os.Getenv("SKIP_MCP_SETUP") != "" {
		log.Println("SKIP_MCP_SETUP is set, skipping e2e ScanSettings and MachineConfigPool setup")
		return nil
	}

	err = f.updateScanSettingsForDebug()
	if err != nil {
		return fmt.Errorf("failed to set scan setting bindings to debug: %w", err)
	}

	if f.useTestPools {
		// Wait for the MachineConfigPool lanes started above and create their
		// ScanSettings, so the destructive/reboot tests can run in parallel,
		// each against its own pool and node. See testpools.go.
		err = f.finishTestPools()
		if err != nil {
			return fmt.Errorf("failed to set up test pools: %w", err)
		}
	} else {
		err = f.ensureE2EScanSettings()
		if err != nil {
			return fmt.Errorf("failed to configure scan settings for tests: %w", err)
		}

		err = f.createMachineConfigPool("e2e")
		if err != nil {
			return fmt.Errorf("failed to create Machine Config Pool %s: %w", "e2e", err)
		}
	}
	err = f.createInvalidMachineConfigPool("e2e-invalid")
	if err != nil {
		return fmt.Errorf("failed to create Machine Config Pool %s: %w", "e2e-invalid", err)
	}

	return nil
}

// tearDown performs any tasks necessary to cleanup resources leftover from testing
// and assumes a specific order. All namespaced resources must be cleaned up before
// deleting the cluster-wide resources, like roles, service accounts, or the deployment.
// If we don't properly cleanup resources before deleting CRDs, it leaves resources in a
// terminating state, making them harder to cleanup.
func (f *Framework) TearDown() error {
	// Stop the pod-log collector first so its log files are flushed and closed
	// before we start deleting resources.
	if f.stopPodLogs != nil {
		f.stopPodLogs()
	}

	// Make sure all scans are cleaned up before we delete the CRDs. Scans should be cleaned up
	// because they're owned by ScanSettingBindings or ScanSuites, which should be cleaned up
	// by each individual test either directly or through deferred cleanup. If the test fails
	// because there are scans that haven't been cleaned up, we could have a bug in the
	// tests.
	err := f.WaitForScanCleanup()
	if err != nil {
		return err
	}

	err = f.cleanUpDefaultProfileBundles()
	if err != nil {
		return err
	}

	if os.Getenv("SKIP_MCP_SETUP") != "" {
		log.Println("SKIP_MCP_SETUP is set, skipping e2e ScanSettings and MachineConfigPool cleanup")
	} else {
		if f.useTestPools {
			// Delete the lanes' ScanSettings. With -restoreTestPools, also move
			// the lane nodes back to the worker pool and delete the lanes. See
			// tearDownTestPools.
			err = f.tearDownTestPools()
			if err != nil {
				return err
			}
		} else {
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
		}
		// e2e-invalid mcp
		err = f.cleanUpMachineConfigPool("e2e-invalid")
		if err != nil {
			return err
		}
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

	return f.deleteOperatorNamespace()
}

// SetUpSuite prepares the cluster for a suite that can run against an
// operator deployed in any of these ways, picked from the environment:
//
//   - by default it deploys the operator from the e2e manifests (SetUp);
//   - with E2E_SKIP_FRAMEWORK_SETUP=true it uses the operator already running
//     in TEST_OPERATOR_NAMESPACE, and never deploys, changes or deletes it;
//   - with E2E_INSTALL_METHOD=subscription it installs the operator through
//     OLM from the CatalogSource that E2E_OLM_SOURCE names (see
//     OLMInstallOptionsFromEnv and InstallOperatorFromCatalog), then goes on
//     as with E2E_SKIP_FRAMEWORK_SETUP.
//
// The last two modes create no e2e MachineConfigPools or ScanSettings and
// leave the operator's default ScanSettings alone, so only suites that use
// neither may call SetUpSuite instead of SetUp. TearDownSuite undoes it.
func (f *Framework) SetUpSuite() error {
	mode, err := chooseSuiteMode(SkipFrameworkSetup(), os.Getenv(InstallMethodEnv), os.Getenv(TestOperatorNamespaceEnv))
	if err != nil {
		return err
	}
	switch mode {
	case suiteModeInstalled:
		log.Printf("%s=true: running against the operator installed in %s", SkipFrameworkSetupEnv, f.OperatorNamespace)
		return f.setUpInstalledOperator()
	case suiteModeSubscription:
		opts, err := OLMInstallOptionsFromEnv()
		if err != nil {
			return err
		}
		if err := f.ensureTestNamespaceExists(); err != nil {
			return fmt.Errorf("unable to create or use namespace %s for testing: %w", f.OperatorNamespace, err)
		}
		f.stopPodLogs = f.StartPodLogCollector()
		f.olmInstallation, err = f.InstallOperatorFromCatalog(opts)
		if err != nil {
			return fmt.Errorf("failed to install the operator through OLM: %w", err)
		}
		return f.setUpInstalledOperator()
	default:
		return f.SetUp()
	}
}

// TearDownSuite undoes SetUpSuite. After a deploy from the manifests it runs
// TearDown. With E2E_SKIP_FRAMEWORK_SETUP=true it only stops the pod-log
// collector: the operator, its namespace and their contents stay. After an
// install through OLM it deletes the default ProfileBundles while the
// operator still runs, uninstalls the operator through its Subscription and
// CSV, and deletes the namespace.
func (f *Framework) TearDownSuite() error {
	if f.olmInstallation != nil {
		return f.tearDownOLMInstallation()
	}
	if SkipFrameworkSetup() {
		if f.stopPodLogs != nil {
			f.stopPodLogs()
		}
		return nil
	}
	return f.TearDown()
}

// suiteMode is where SetUpSuite gets the operator from.
type suiteMode int

const (
	suiteModeManifest suiteMode = iota
	suiteModeInstalled
	suiteModeSubscription
)

// chooseSuiteMode picks the suite mode from the values of
// E2E_SKIP_FRAMEWORK_SETUP, E2E_INSTALL_METHOD and TEST_OPERATOR_NAMESPACE.
func chooseSuiteMode(skipSetup bool, installMethod, operatorNamespace string) (suiteMode, error) {
	switch installMethod {
	case "", InstallMethodManifest:
		if !skipSetup {
			return suiteModeManifest, nil
		}
		if operatorNamespace == "" {
			return 0, fmt.Errorf("%s=true needs %s, the namespace the installed operator runs in",
				SkipFrameworkSetupEnv, TestOperatorNamespaceEnv)
		}
		return suiteModeInstalled, nil
	case InstallMethodSubscription:
		if skipSetup {
			return 0, fmt.Errorf("%s=true uses an operator that is already installed, so it doesn't combine with %s=%s",
				SkipFrameworkSetupEnv, InstallMethodEnv, InstallMethodSubscription)
		}
		return suiteModeSubscription, nil
	default:
		return 0, fmt.Errorf("unknown %s %q, want %q or %q",
			InstallMethodEnv, installMethod, InstallMethodManifest, InstallMethodSubscription)
	}
}

// setUpInstalledOperator prepares a suite to run against the operator that
// already runs in f.OperatorNamespace, without deploying, changing or
// deleting it: it registers the API types, creates the resources the metrics
// tests read the operator's metrics with, and waits for the operator and its
// default ProfileBundles.
func (f *Framework) setUpInstalledOperator() error {
	if f.projectRoot != "" {
		log.Printf("switching to %s directory to execute tests", f.projectRoot)
		if err := os.Chdir(f.projectRoot); err != nil {
			return fmt.Errorf("failed to change directory to project root: %w", err)
		}
	}

	if err := f.waitForInstalledOperator(); err != nil {
		return err
	}

	if f.stopPodLogs == nil {
		f.stopPodLogs = f.StartPodLogCollector()
	}

	if err := f.addFrameworks(); err != nil {
		return err
	}

	if err := f.initializeMetricsTestResources(); err != nil {
		return fmt.Errorf("failed to initialize cluster resources for metrics: %w", err)
	}

	return f.waitForDefaultProfileBundles()
}

// waitForInstalledOperator waits for the compliance-operator Deployment in
// f.OperatorNamespace to be available, and fails right away if there is none.
func (f *Framework) waitForInstalledOperator() error {
	const name = "compliance-operator"
	_, err := f.KubeClient.AppsV1().Deployments(f.OperatorNamespace).Get(context.TODO(), name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("no %s Deployment in namespace %s, set %s to the namespace the operator is installed in",
			name, f.OperatorNamespace, TestOperatorNamespaceEnv)
	}
	if err != nil {
		return fmt.Errorf("failed to get the %s Deployment in namespace %s: %w", name, f.OperatorNamespace, err)
	}
	return f.WaitForDeployment(name, 1, RetryInterval, cleanupTimeout)
}

// tearDownOLMInstallation removes the operator SetUpSuite installed through
// OLM, and its namespace.
func (f *Framework) tearDownOLMInstallation() error {
	if f.stopPodLogs != nil {
		f.stopPodLogs()
	}

	err := f.WaitForScanCleanup()
	if err != nil {
		return err
	}

	// The operator removes the ProfileBundles' finalizers, so they have to
	// be gone before it is.
	err = f.cleanUpDefaultProfileBundles()
	if err != nil {
		return err
	}
	for _, name := range []string{"rhcos4", "ocp4"} {
		pb := &compv1alpha1.ProfileBundle{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: f.OperatorNamespace}}
		if err := f.waitForDeletion(pb, cleanupTimeout); err != nil {
			return err
		}
	}

	err = f.UninstallOperator(f.olmInstallation)
	if err != nil {
		return err
	}

	return f.deleteOperatorNamespace()
}

// waitForDefaultProfileBundles waits for the ProfileBundles the operator
// creates at startup to be parsed: ocp4, and rhcos4 on the architectures
// that ship it.
func (f *Framework) waitForDefaultProfileBundles() error {
	arch := f.ClusterArchitecture()
	if ExpectsRhcos4ProfileBundle(arch) {
		if err := f.WaitForProfileBundleStatus("rhcos4", compv1alpha1.DataStreamValid); err != nil {
			return err
		}
	} else {
		log.Printf("skipping rhcos4 ProfileBundle wait for architecture %s", arch.String())
	}
	return f.WaitForProfileBundleStatus("ocp4", compv1alpha1.DataStreamValid)
}

// cleanUpDefaultProfileBundles deletes the ProfileBundles the operator
// creates at startup.
func (f *Framework) cleanUpDefaultProfileBundles() error {
	log.Printf("cleaning up Profile Bundles")
	arch := f.ClusterArchitecture()
	if ExpectsRhcos4ProfileBundle(arch) {
		if err := f.cleanUpProfileBundle("rhcos4"); err != nil {
			return fmt.Errorf("failed to cleanup rhcos4 profile bundle: %w", err)
		}
	} else {
		log.Printf("skipping rhcos4 ProfileBundle cleanup for architecture %s", arch.String())
	}

	if err := f.cleanUpProfileBundle("ocp4"); err != nil {
		return fmt.Errorf("failed to cleanup ocp4 profile bundle: %w", err)
	}
	return nil
}

// deleteOperatorNamespace deletes the operator namespace and waits for it to
// be gone.
func (f *Framework) deleteOperatorNamespace() error {
	log.Printf("cleaning up namespace %s\n", f.OperatorNamespace)
	err := f.KubeClient.CoreV1().Namespaces().Delete(context.TODO(), f.OperatorNamespace, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to cleanup namespace %s: %w", f.OperatorNamespace, err)
	}

	// Verify namespace deletion completes successfully
	// This ensures that all resources, including those with finalizers, are properly cleaned up
	// and that the operator can be deleted without resources getting stuck in terminating state
	log.Printf("Verifying namespace %s deletion \n", f.OperatorNamespace)
	err = f.waitForNamespaceDeletion(f.OperatorNamespace, time.Second*5, time.Minute*5)
	if err != nil {
		return fmt.Errorf("namespace %s deletion did not complete: %w", f.OperatorNamespace, err)
	}
	log.Printf("Namespace %s successfully deleted\n", f.OperatorNamespace)
	return nil
}
