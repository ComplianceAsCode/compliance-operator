package deployment_e2e

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"testing"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestMustGatherImageWorksAsExpected(t *testing.T) {
	t.Parallel()
	f := framework.Global

	suiteName := framework.GetObjNameFromTest(t)
	scanSettingBindingName := suiteName

	// must-gather only needs some scans and results: bind TailoredProfiles of
	// the small E8 profiles, named after this test, on masters and spares.
	ss := f.WorkerScanSetting(t, suiteName+"-ss")
	tpPlatform := f.ExtendingTailoredProfile(t, suiteName+"-ocp4-e8", "ocp4-e8")
	tpNode := f.ExtendingTailoredProfile(t, suiteName+"-rhcos4-e8", "rhcos4-e8")

	// Create ScanSettingBinding to trigger compliance scans
	scanSettingBinding := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingBindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     tpPlatform.Name,
				Kind:     "TailoredProfile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
			{
				Name:     tpNode.Name,
				Kind:     "TailoredProfile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			Name:     ss.Name,
			Kind:     "ScanSetting",
			APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}

	err := f.Client.Create(context.TODO(), scanSettingBinding, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), scanSettingBinding)

	// Wait for the ComplianceSuite scans to complete
	log.Printf("Waiting for ComplianceSuite scans to complete...")
	err = f.WaitForSuiteScansStatusAnyResult(f.OperatorNamespace, scanSettingBindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant, compv1alpha1.ResultInconsistent)
	if err != nil {
		t.Fatalf("Scan did not complete successfully: %v", err)
	}
	log.Printf("ComplianceSuite scans completed")

	// Verify that compliance resources exist before running must-gather
	// If these resources don't exist, must-gather will fail or produce incomplete results
	log.Printf("Verifying compliance resources exist in namespace %s...", f.OperatorNamespace)

	var scans compv1alpha1.ComplianceScanList
	if err := f.Client.List(context.TODO(), &scans, &client.ListOptions{Namespace: f.OperatorNamespace}); err != nil {
		t.Fatalf("Failed to list ComplianceScans: %v", err)
	}
	log.Printf("Found %d ComplianceScans in namespace", len(scans.Items))
	if len(scans.Items) == 0 {
		t.Fatal("No ComplianceScans found - cannot verify must-gather functionality")
	}

	var suites compv1alpha1.ComplianceSuiteList
	if err := f.Client.List(context.TODO(), &suites, &client.ListOptions{Namespace: f.OperatorNamespace}); err != nil {
		t.Fatalf("Failed to list ComplianceSuites: %v", err)
	}
	log.Printf("Found %d ComplianceSuites in namespace", len(suites.Items))
	if len(suites.Items) == 0 {
		t.Fatal("No ComplianceSuites found - cannot verify must-gather functionality")
	}

	var checkResults compv1alpha1.ComplianceCheckResultList
	if err := f.Client.List(context.TODO(), &checkResults, &client.ListOptions{Namespace: f.OperatorNamespace}); err != nil {
		t.Fatalf("Failed to list ComplianceCheckResults: %v", err)
	}
	log.Printf("Found %d ComplianceCheckResults in namespace", len(checkResults.Items))
	if len(checkResults.Items) == 0 {
		t.Fatal("No ComplianceCheckResults found - cannot verify must-gather functionality")
	}

	// Get the must-gather image
	// In upstream, we use an environment variable or default image since there's no CSV
	mustGatherImage := getMustGatherImage(f)
	log.Printf("Must-gather image: %s", mustGatherImage)

	// Create a temporary directory for must-gather output
	mustGatherDir := fmt.Sprintf("/tmp/must-gather-%s", suiteName)
	defer os.RemoveAll(mustGatherDir)

	// Execute must-gather
	log.Printf("Executing must-gather with image %s to directory %s...", mustGatherImage, mustGatherDir)
	mustGatherOutput, err := runOCandGetOutput([]string{
		"adm", "must-gather",
		"--image=" + mustGatherImage,
		"--dest-dir=" + mustGatherDir,
	})
	if err != nil {
		t.Fatalf("Failed to execute must-gather: %v\nOutput: %s", err, mustGatherOutput)
	}

	log.Printf("Must-gather completed successfully")

	// Verify the must-gather output directory exists
	if _, err := os.Stat(mustGatherDir); os.IsNotExist(err) {
		t.Fatalf("Must-gather directory does not exist: %s", mustGatherDir)
	}

	// Verify essential files and directories are present in must-gather output
	failureCount := verifyMustGatherContents(mustGatherDir, f.OperatorNamespace, t)
	if failureCount > 0 {
		t.Fatalf("%d must-gather content verification failures", failureCount)
	}

	log.Printf("Must-gather content verification passed")
}

// getMustGatherImage retrieves the must-gather image to use for the test
// It tries the following in order:
// 1. MUST_GATHER_IMAGE environment variable
// 2. Try to get it from CSV (if OLM is being used)
// 3. Fall back to the default upstream image
func getMustGatherImage(f *framework.Framework) string {
	// Check for environment variable first
	if mgImage := os.Getenv("MUST_GATHER_IMAGE"); mgImage != "" {
		log.Printf("Using must-gather image from MUST_GATHER_IMAGE env var: %s", mgImage)
		return mgImage
	}

	// Try to get from CSV if OLM is present (for OLM deployments)
	if isOLMPresent(f) {
		log.Printf("OLM detected, attempting to get must-gather image from CSV...")
		csvImage, err := getMustGatherImageFromCSV(f)
		if err != nil {
			log.Printf("Failed to get must-gather image from CSV: %v, falling back to default", err)
		} else if csvImage != "" {
			log.Printf("Using must-gather image from CSV: %s", csvImage)
			return csvImage
		}
	} else {
		log.Printf("OLM not detected, skipping CSV image lookup")
	}

	// Fall back to default upstream image
	defaultImage := "quay.io/redhat-user-workloads/ocp-isc-tenant/compliance-operator-must-gather-dev:master"
	log.Printf("Using default must-gather image: %s", defaultImage)
	return defaultImage
}

// isOLMPresent checks if OLM is available in the cluster
// by attempting to list ClusterServiceVersions using the API
func isOLMPresent(f *framework.Framework) bool {
	csvList := &unstructured.UnstructuredList{}
	csvList.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "operators.coreos.com",
		Version: "v1alpha1",
		Kind:    "ClusterServiceVersionList",
	})

	err := f.Client.List(context.TODO(), csvList, &client.ListOptions{Namespace: f.OperatorNamespace})
	return err == nil
}

// getMustGatherImageFromCSV retrieves the must-gather image reference from the CSV
// Returns an error if CSV doesn't exist or doesn't have the must-gather image
func getMustGatherImageFromCSV(f *framework.Framework) (string, error) {
	// List all CSVs in the operator namespace
	csvList := &unstructured.UnstructuredList{}
	csvList.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "operators.coreos.com",
		Version: "v1alpha1",
		Kind:    "ClusterServiceVersionList",
	})

	err := f.Client.List(context.TODO(), csvList, &client.ListOptions{Namespace: f.OperatorNamespace})
	if err != nil {
		return "", fmt.Errorf("failed to list CSVs: %w", err)
	}

	if len(csvList.Items) == 0 {
		return "", fmt.Errorf("no CSV found in namespace %s", f.OperatorNamespace)
	}

	// Find the compliance-operator CSV by checking the name prefix
	var csv *unstructured.Unstructured
	for i := range csvList.Items {
		csvItem := &csvList.Items[i]
		if name := csvItem.GetName(); name != "" {
			// CSVs typically have names like "compliance-operator.vX.Y.Z"
			if strings.HasPrefix(name, "compliance-operator") {
				csv = csvItem
				break
			}
		}
	}

	if csv == nil {
		return "", fmt.Errorf("no compliance-operator CSV found in namespace %s", f.OperatorNamespace)
	}

	// Extract the must-gather image from relatedImages
	relatedImages, found, err := unstructured.NestedSlice(csv.Object, "spec", "relatedImages")
	if err != nil {
		return "", fmt.Errorf("failed to get relatedImages from CSV: %w", err)
	}
	if !found {
		return "", fmt.Errorf("relatedImages not found in CSV %s", csv.GetName())
	}

	// Find the must-gather image
	for _, imgObj := range relatedImages {
		img, ok := imgObj.(map[string]interface{})
		if !ok {
			continue
		}
		name, found, err := unstructured.NestedString(img, "name")
		if err != nil || !found {
			continue
		}
		if name == "must-gather" {
			image, found, err := unstructured.NestedString(img, "image")
			if err != nil {
				return "", fmt.Errorf("failed to get image field: %w", err)
			}
			if !found || image == "" {
				return "", fmt.Errorf("must-gather image field is empty in CSV %s", csv.GetName())
			}
			return image, nil
		}
	}

	return "", fmt.Errorf("must-gather image not found in CSV %s relatedImages", csv.GetName())
}

// runOCandGetOutput runs an oc command and returns the output
func runOCandGetOutput(args []string) (string, error) {
	ocPath, err := exec.LookPath("oc")
	if err != nil {
		return "", fmt.Errorf("failed to find oc binary: %v", err)
	}

	cmd := exec.Command(ocPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("failed to run oc command: %v", err)
	}
	return string(out), nil
}

// verifyMustGatherContents verifies the expected files and directories are present in the must-gather output
func verifyMustGatherContents(mustGatherDir, namespace string, t *testing.T) int {
	failureCount := 0

	log.Printf("Verifying must-gather contents in %s", mustGatherDir)

	// Check if the directory has subdirectories (must-gather creates a timestamp directory)
	entries, err := os.ReadDir(mustGatherDir)
	if err != nil {
		t.Logf("Failed to read must-gather directory: %v", err)
		failureCount++
		return failureCount
	}

	if len(entries) == 0 {
		t.Logf("Must-gather directory is empty")
		failureCount++
		return failureCount
	}

	// must-gather creates a timestamped directory (e.g., must-gather.local.123456)
	// We need to find it first
	var timestampDir string
	for _, entry := range entries {
		if entry.IsDir() {
			timestampDir = fmt.Sprintf("%s/%s", mustGatherDir, entry.Name())
			log.Printf("Found timestamped directory: %s", entry.Name())
			break
		}
	}

	if timestampDir == "" {
		t.Logf("Could not find timestamped must-gather directory")
		failureCount++
		return failureCount
	}

	// List all directories in timestamped directory for debugging
	timestampEntries, err := os.ReadDir(timestampDir)
	if err == nil {
		log.Printf("Contents of timestamped directory:")
		for _, entry := range timestampEntries {
			if entry.IsDir() {
				log.Printf("  - %s (directory)", entry.Name())
			} else {
				log.Printf("  - %s (file)", entry.Name())
			}
		}
	}

	// The must-gather data is written directly to the timestamped directory
	// Verify compliance operator namespace directory exists
	complianceNamespaceDir := fmt.Sprintf("%s/%s", timestampDir, namespace)
	if _, err := os.Stat(complianceNamespaceDir); os.IsNotExist(err) {
		t.Logf("namespace directory %s not found at %s", namespace, complianceNamespaceDir)
		failureCount++
		return failureCount
	}

	log.Printf("Found namespace directory: %s", namespace)

	// List all directories in compliance operator namespace for debugging
	complianceEntries, err := os.ReadDir(complianceNamespaceDir)
	if err == nil {
		log.Printf("Contents of %s namespace directory:", namespace)
		for _, entry := range complianceEntries {
			if entry.IsDir() {
				log.Printf("  - %s (directory)", entry.Name())
			} else {
				log.Printf("  - %s (file)", entry.Name())
			}
		}
	}

	// Verify essential subdirectories exist
	// Note: The gather script currently hardcodes "openshift-compliance" for pods/configmaps
	// (see gather_compliance lines 49-67), so we check there regardless of actual operator namespace
	// TODO: This should be fixed in the gather script to use the actual operator namespace
	essentialDirs := []string{"pods", "configmaps"}
	openshiftComplianceDir := fmt.Sprintf("%s/openshift-compliance", timestampDir)
	for _, dir := range essentialDirs {
		dirPath := fmt.Sprintf("%s/%s", openshiftComplianceDir, dir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			t.Logf("Expected directory %s not found in openshift-compliance", dir)
			failureCount++
		} else {
			log.Printf("Found %s directory in openshift-compliance", dir)
		}
	}

	// Check for compliance CRD directories (all should exist since we're using a ScanSettingBinding)
	// Note: These are created by the gather script at lines 8-20 of gather_compliance
	// They are only present if there are actual CRD instances in the namespace
	complianceCRDs := []string{
		"compliancescans.compliance.openshift.io",
		"compliancesuites.compliance.openshift.io",
		"compliancecheckresults.compliance.openshift.io",
	}

	// Search for CRD directories in multiple locations
	// The gather script may place them in different directories depending on the environment
	foundCRDs := searchCRDDirectories(complianceCRDs, complianceNamespaceDir, timestampDir, namespace)

	// Log results
	if len(foundCRDs) < len(complianceCRDs) {
		missingCRDs := []string{}
		for _, crd := range complianceCRDs {
			if !foundCRDs[crd] {
				missingCRDs = append(missingCRDs, crd)
			}
		}
		t.Logf("ERROR: Not all compliance CRD directories found. Missing: %v", missingCRDs)
		t.Logf("Found: %d/%d CRD directories", len(foundCRDs), len(complianceCRDs))
		t.Logf("This indicates the gather script failed to collect CRD data - check gather.logs")
		log.Printf("ERROR: Missing CRD directories %v - this is a must-gather bug", missingCRDs)
		failureCount++
	}

	return failureCount
}

// searchCRDDirectories searches for CRD directories in multiple locations and returns a map of found CRDs.
// It searches in order: compliance namespace dir, parent timestamp dir, other namespace dirs.
// Returns early once all CRDs are found to optimize performance.
func searchCRDDirectories(crdNames []string, complianceNamespaceDir, timestampDir, namespace string) map[string]bool {
	foundCRDs := make(map[string]bool)
	searchLocations := []struct {
		name        string
		getPathFunc func(string) []string
	}{
		{
			name: "compliance namespace directory",
			getPathFunc: func(crd string) []string {
				return []string{fmt.Sprintf("%s/%s", complianceNamespaceDir, crd)}
			},
		},
		{
			name: "parent timestamp directory",
			getPathFunc: func(crd string) []string {
				return []string{fmt.Sprintf("%s/%s", timestampDir, crd)}
			},
		},
		{
			name: "other namespace directories",
			getPathFunc: func(crd string) []string {
				var paths []string
				if entries, err := os.ReadDir(timestampDir); err == nil {
					for _, entry := range entries {
						if entry.IsDir() && entry.Name() != namespace && entry.Name() != "gather.logs" {
							paths = append(paths, fmt.Sprintf("%s/%s/%s", timestampDir, entry.Name(), crd))
						}
					}
				}
				return paths
			},
		},
	}

	for _, location := range searchLocations {
		if len(foundCRDs) == len(crdNames) {
			break // All CRDs found, no need to continue searching
		}

		for _, crd := range crdNames {
			if foundCRDs[crd] {
				continue // Already found this CRD
			}

			for _, path := range location.getPathFunc(crd) {
				if _, err := os.Stat(path); err == nil {
					log.Printf("Found CRD directory in %s: %s", location.name, crd)
					foundCRDs[crd] = true
					break
				}
			}
		}
	}

	return foundCRDs
}
