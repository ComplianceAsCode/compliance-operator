package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

// OperatorHub's infrastructure feature filters, such as Disconnected, list an
// operator by the features its CSV annotations declare. OCP-40280 checks that
// the installed CSV lists these in this annotation.
const infrastructureFeaturesAnnotation = "operators.openshift.io/infrastructure-features"

var infrastructureFeatures = []string{"disconnected", "fips", "proxy-aware"}

const (
	baseCSV   = "../config/manifests/bases/compliance-operator.clusterserviceversion.yaml"
	bundleCSV = "../bundle/manifests/compliance-operator.clusterserviceversion.yaml"
)

func csvAnnotations(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var csv map[string]interface{}
	if err := yaml.Unmarshal(data, &csv); err != nil {
		t.Fatalf("failed to parse %s: %v", path, err)
	}
	metadata, _ := csv["metadata"].(map[string]interface{})
	annotations, ok := metadata["annotations"].(map[string]interface{})
	if !ok {
		t.Fatalf("%s has no metadata.annotations", path)
	}
	return annotations
}

func expectInfrastructureFeatures(t *testing.T, path string, annotations map[string]interface{}) {
	t.Helper()
	value, ok := annotations[infrastructureFeaturesAnnotation].(string)
	if !ok {
		t.Fatalf("%s has no %s annotation", path, infrastructureFeaturesAnnotation)
	}
	var features []string
	if err := json.Unmarshal([]byte(value), &features); err != nil {
		t.Fatalf("%s: %s %q is not a JSON list: %v", path, infrastructureFeaturesAnnotation, value, err)
	}
	for _, feature := range infrastructureFeatures {
		if !slices.Contains(features, feature) {
			t.Errorf("%s: %s %s doesn't list %q", path, infrastructureFeaturesAnnotation, value, feature)
		}
	}
}

// The annotation is kept in the base CSV, and make bundle copies it to the
// bundle CSV, which bundle.openshift.Dockerfile passes to update_csv.go.
func TestCSVInfrastructureFeatures(t *testing.T) {
	for _, tc := range []struct{ name, path string }{
		{"base", baseCSV},
		{"bundle", bundleCSV},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expectInfrastructureFeatures(t, tc.path, csvAnnotations(t, tc.path))
		})
	}
}

// TestUpdateCSVInfrastructureFeatures runs update_csv.go as
// bundle.openshift.Dockerfile does, on a copy of the bundle CSV, and checks the
// CSV it writes, which is the one the Red Hat catalog ships.
func TestUpdateCSVInfrastructureFeatures(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile(bundleCSV)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filepath.Base(bundleCSV)), data, 0o600); err != nil {
		t.Fatal(err)
	}

	// The versions only go into the CSV's name, version, replaces and skipRange.
	const oldVersion, newVersion = "0.0.1", "0.0.2"
	args := os.Args
	defer func() { os.Args = args }()
	os.Args = []string{"update_csv", dir, oldVersion, newVersion}
	main()

	path := getOutputCSVFilePath(dir, newVersion)
	annotations := csvAnnotations(t, path)
	expectInfrastructureFeatures(t, path, annotations)
	// OperatorHub also reads the newer annotations that update_csv.go adds.
	for _, key := range []string{
		"features.operators.openshift.io/disconnected",
		"features.operators.openshift.io/fips-compliant",
	} {
		if value := annotations[key]; value != "true" {
			t.Errorf("%s: %s is %v, want \"true\"", path, key, value)
		}
	}
}
