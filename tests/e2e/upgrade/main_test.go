package upgrade_e2e

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	apiv1alpha1 "github.com/operator-framework/api/pkg/operators/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestMain(m *testing.M) {
	f := framework.NewFramework()
	err := f.SetUp()
	if err != nil {
		log.Fatal(err)
	}

	// Upgrade tests don't require content images like scan tests do
	// They work with the operator installation from OLM

	exitCode := m.Run()
	if exitCode == 0 || (exitCode > 0 && f.CleanUpOnError()) {
		if err = f.TearDown(); err != nil {
			log.Fatal(err)
		}
	}
	os.Exit(exitCode)
}

func TestOperatorUpgradeResourcesAndMCPStability(t *testing.T) {
	// Check if upgrade testing is configured
	upgradeCatalogImage := os.Getenv("UPGRADE_CATALOG_SOURCE_IMAGE")
	startingCSV := os.Getenv("STARTING_CSV")

	if upgradeCatalogImage == "" || startingCSV == "" {
		t.Skip("Skipping upgrade test: UPGRADE_CATALOG_SOURCE_IMAGE and STARTING_CSV must be set")
	}

	f := framework.Global

	log.Printf("Running operator upgrade test from %s to catalog image %s", startingCSV, upgradeCatalogImage)

	// PRE-UPGRADE CHECKS
	log.Print("PRE-UPGRADE: Checking MachineConfigPool status")
	if err := f.WaitForMachineConfigPoolToBeHealthy("master", 15*time.Minute); err != nil {
		t.Fatalf("Master MachineConfigPool is not healthy before upgrade: %v", err)
	}
	if err := f.WaitForMachineConfigPoolToBeHealthy("worker", 15*time.Minute); err != nil {
		t.Fatalf("Worker MachineConfigPool is not healthy before upgrade: %v", err)
	}

	log.Print("PRE-UPGRADE: Capturing resource snapshot")
	beforeSnapshot, err := f.GetResourceSnapshot(f.OperatorNamespace)
	if err != nil {
		t.Fatalf("Failed to get resource snapshot before upgrade: %v", err)
	}

	// Sanity check - ensure we have resources to track
	if len(beforeSnapshot.RuleNames) == 0 {
		t.Fatal("Expected to find rules before upgrade, but found none")
	}
	if len(beforeSnapshot.ProfileNames) == 0 {
		t.Fatal("Expected to find profiles before upgrade, but found none")
	}

	log.Printf("Resource snapshot before upgrade - Rules: %d, Variables: %d, Profiles: %d",
		len(beforeSnapshot.RuleNames), len(beforeSnapshot.VariableNames), len(beforeSnapshot.ProfileNames))

	// PERFORM UPGRADE
	log.Print("UPGRADE: Setting up upgrade catalog source")

	// Create CatalogSource if it doesn't exist
	catalogSourceName := "compliance-operator-upgrade"
	catalogSourceNS := "openshift-marketplace"

	catalogSource := &apiv1alpha1.CatalogSource{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{
		Name:      catalogSourceName,
		Namespace: catalogSourceNS,
	}, catalogSource)

	if apierrors.IsNotFound(err) {
		// CatalogSource doesn't exist, create it
		log.Printf("Creating CatalogSource %s from image: %s", catalogSourceName, upgradeCatalogImage)

		catalogSource = &apiv1alpha1.CatalogSource{
			ObjectMeta: metav1.ObjectMeta{
				Name:      catalogSourceName,
				Namespace: catalogSourceNS,
			},
			Spec: apiv1alpha1.CatalogSourceSpec{
				SourceType:  apiv1alpha1.SourceTypeGrpc,
				Image:       upgradeCatalogImage,
				DisplayName: "Compliance Operator Upgrade Test",
				Publisher:   "OpenShift QE",
				UpdateStrategy: &apiv1alpha1.UpdateStrategy{
					RegistryPoll: &apiv1alpha1.RegistryPoll{
						Interval: &metav1.Duration{Duration: 15 * time.Minute},
					},
				},
			},
		}

		err = f.Client.Create(context.TODO(), catalogSource, nil)
		if err != nil {
			t.Fatalf("Failed to create CatalogSource: %v", err)
		}
		log.Printf("CatalogSource %s created", catalogSourceName)

		// Clean up CatalogSource after test
		defer func() {
			log.Printf("Cleaning up CatalogSource %s", catalogSourceName)
			f.Client.Delete(context.TODO(), catalogSource)
		}()

		// Wait for CatalogSource to be READY
		log.Print("Waiting for CatalogSource to become READY...")
		err = wait.Poll(10*time.Second, 5*time.Minute, func() (bool, error) {
			cs := &apiv1alpha1.CatalogSource{}
			err := f.Client.Get(context.TODO(), types.NamespacedName{
				Name:      catalogSourceName,
				Namespace: catalogSourceNS,
			}, cs)
			if err != nil {
				return false, err
			}

			if cs.Status.GRPCConnectionState != nil &&
				cs.Status.GRPCConnectionState.LastObservedState == "READY" {
				log.Printf("CatalogSource is READY")
				return true, nil
			}
			return false, nil
		})
		if err != nil {
			t.Fatalf("Timeout waiting for CatalogSource to be READY: %v", err)
		}
	} else if err != nil {
		t.Fatalf("Failed to check if CatalogSource exists: %v", err)
	} else {
		log.Printf("CatalogSource %s already exists", catalogSourceName)
	}

	// Now perform the upgrade
	log.Print("UPGRADE: Patching subscription to trigger upgrade")

	// Get current CSV name for comparison
	currentCSV := &corev1.ObjectReference{}
	sub := &apiv1alpha1.Subscription{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{
		Name:      "compliance-operator",
		Namespace: f.OperatorNamespace,
	}, sub)
	if err != nil {
		t.Fatalf("Failed to get subscription: %v", err)
	}

	if sub.Status.InstalledCSV != "" {
		currentCSV.Name = sub.Status.InstalledCSV
		log.Printf("Current CSV: %s", currentCSV.Name)
	} else {
		t.Fatal("No installed CSV found in subscription status")
	}

	// Patch subscription to use upgrade catalog source
	// This assumes a CatalogSource named "compliance-operator-upgrade" exists
	log.Print("Patching subscription to use upgrade catalog source...")
	subPatch := []byte(`{
		"spec": {
			"source": "compliance-operator-upgrade",
			"installPlanApproval": "Automatic"
		}
	}`)

	err = f.Client.Patch(context.TODO(), sub, client.RawPatch(types.MergePatchType, subPatch))
	if err != nil {
		t.Fatalf("Failed to patch subscription: %v", err)
	}

	log.Print("Waiting for new InstallPlan to be created...")
	time.Sleep(10 * time.Second) // Give OLM time to create new InstallPlan

	// Find and approve the new InstallPlan
	var newInstallPlan *apiv1alpha1.InstallPlan
	err = wait.Poll(5*time.Second, 2*time.Minute, func() (bool, error) {
		ipList := &apiv1alpha1.InstallPlanList{}
		listOpts := &client.ListOptions{Namespace: f.OperatorNamespace}
		err := f.Client.List(context.TODO(), ipList, listOpts)
		if err != nil {
			return false, err
		}

		for i := range ipList.Items {
			ip := &ipList.Items[i]
			// Find InstallPlan that's for a different CSV than current
			if len(ip.Spec.ClusterServiceVersionNames) > 0 {
				csvName := ip.Spec.ClusterServiceVersionNames[0]
				if csvName != currentCSV.Name && !ip.Spec.Approved {
					newInstallPlan = ip
					log.Printf("Found new InstallPlan: %s for CSV: %s", ip.Name, csvName)
					return true, nil
				}
			}
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("Failed to find new InstallPlan: %v", err)
	}

	// Approve the InstallPlan
	log.Printf("Approving InstallPlan: %s", newInstallPlan.Name)
	newInstallPlan.Spec.Approved = true
	err = f.Client.Update(context.TODO(), newInstallPlan)
	if err != nil {
		t.Fatalf("Failed to approve InstallPlan: %v", err)
	}

	// Wait for new CSV to be installed
	log.Print("Waiting for new CSV to reach Succeeded phase...")
	err = wait.Poll(10*time.Second, 10*time.Minute, func() (bool, error) {
		csvList := &apiv1alpha1.ClusterServiceVersionList{}
		listOpts := &client.ListOptions{Namespace: f.OperatorNamespace}
		err := f.Client.List(context.TODO(), csvList, listOpts)
		if err != nil {
			return false, err
		}

		for i := range csvList.Items {
			csv := &csvList.Items[i]
			if csv.Name != currentCSV.Name && csv.Status.Phase == apiv1alpha1.CSVPhaseSucceeded {
				log.Printf("New CSV %s reached Succeeded phase", csv.Name)
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("Timeout waiting for new CSV to be installed: %v", err)
	}

	log.Print("Operator upgrade completed successfully!")

	// POST-UPGRADE CHECKS
	log.Print("POST-UPGRADE: Checking MachineConfigPool status")
	if err := f.WaitForMachineConfigPoolToBeHealthy("master", 15*time.Minute); err != nil {
		t.Fatalf("Master MachineConfigPool is not healthy after upgrade: %v", err)
	}
	if err := f.WaitForMachineConfigPoolToBeHealthy("worker", 15*time.Minute); err != nil {
		t.Fatalf("Worker MachineConfigPool is not healthy after upgrade: %v", err)
	}

	log.Print("POST-UPGRADE: Capturing resource snapshot")
	afterSnapshot, err := f.GetResourceSnapshot(f.OperatorNamespace)
	if err != nil {
		t.Fatalf("Failed to get resource snapshot after upgrade: %v", err)
	}

	log.Printf("Resource snapshot after upgrade - Rules: %d, Variables: %d, Profiles: %d",
		len(afterSnapshot.RuleNames), len(afterSnapshot.VariableNames), len(afterSnapshot.ProfileNames))

	// VALIDATE: Resources should not be lost during upgrade
	log.Print("VALIDATION: Comparing resource snapshots")
	diff, err := f.CompareResourceSnapshots(beforeSnapshot, afterSnapshot, "after upgrade")
	if err != nil {
		// When upgrade causes resource loss, show exactly what was removed
		t.Fatalf("UPGRADE VALIDATION FAILED - Resources were lost:\n%v\n\nDetailed diff:\n%s",
			err, diff.String())
	}

	// Log any changes (additions are expected in upgrades, removals are failures)
	if diff.HasChanges() {
		log.Printf("Resource changes during upgrade:\n%s", diff.String())
		if len(diff.AddedRules) > 0 || len(diff.AddedVariables) > 0 || len(diff.AddedProfiles) > 0 {
			log.Print("New resources were added during upgrade (this is expected)")
		}
	} else {
		log.Print("No resource changes during upgrade")
	}

	log.Print("=== SUCCESS ===")
	log.Print("Operator upgrade validation passed:")
	log.Print("MachineConfigPools remained healthy")
	log.Print("No resources were lost")
	log.Print("Resource tracking functions work correctly")
}
