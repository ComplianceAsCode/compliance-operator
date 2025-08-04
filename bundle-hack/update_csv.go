package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Konflux pull specs used across multiple functions
var (
	konfluxOperatorPullSpec   = "quay.io/redhat-user-workloads/ocp-isc-tenant/compliance-operator-release@sha256:0a5629fd6f6b77cb36734eb663b847f51d45050532cb895c821e00416a1324e4"
	konfluxContentPullSpec    = "quay.io/redhat-user-workloads/ocp-isc-tenant/compliance-operator-content-release@sha256:509466d3058ec82f280ac469b400f295a52db7edd2fe526b413162c76be79628"
	konfluxOpenscapPullSpec   = "quay.io/redhat-user-workloads/ocp-isc-tenant/compliance-operator-openscap-release@sha256:d0f89d82845c6245a18e7db345ac3be92b2863d57f55f63e21652086128920c9"
	konfluxMustGatherPullSpec = "quay.io/redhat-user-workloads/ocp-isc-tenant/compliance-operator-must-gather-release@sha256:e6468ccc55d72539b7fb980d0bce5c072e85879d4e9db39974d53eaab4d32b25"
)

func readCSV(csvFilename string, csv *map[string]interface{}) {
	yamlFile, err := os.ReadFile(csvFilename)
	if err != nil {
		log.Fatal(fmt.Sprintf("Error: Failed to read file '%s'", csvFilename))
	}

	err = yaml.Unmarshal(yamlFile, csv)
	if err != nil {
		log.Fatal(fmt.Sprintf("Error: Failed to unmarshal yaml file '%s'", csvFilename))
	}
}

func replaceCSV(csvFilename string, outputCSVFilename string, csv map[string]interface{}) {
	err := os.Remove(csvFilename)
	if err != nil {
		log.Fatal(fmt.Sprintf("Error: Failed to remofe file '%s'", csvFilename))
	}

	f, err := os.Create(outputCSVFilename)
	if err != nil {
		log.Fatal(fmt.Sprintf("Error: Failed to create file '%s'", outputCSVFilename))
	}

	enc := yaml.NewEncoder(f)
	defer enc.Close()
	enc.SetIndent(2)

	err = enc.Encode(csv)
	if err != nil {
		log.Fatal("Error: Failed encode the CSV into yaml")
	}
}

func getInputCSVFilePath(dir string) string {
	filenames, err := os.ReadDir(dir)
	if err != nil {
		log.Fatal("Failed to find manifest dir")
	}

	for _, filename := range filenames {
		if strings.HasSuffix(filename.Name(), "clusterserviceversion.yaml") {
			return filepath.Join(dir, filename.Name())
		}
	}

	log.Fatal("Failed to find CSV file in manifest dir")
	return ""
}

func getOutputCSVFilePath(dir string, version string) string {
	return filepath.Join(dir, fmt.Sprintf("compliance-operator.v%s.clusterserviceversion.yaml", version))
}

func addRequiredAnnotations(csv map[string]interface{}) {
	requiredAnnotations := map[string]string{
		"features.operators.openshift.io/cnf":              "false",
		"features.operators.openshift.io/cni":              "false",
		"features.operators.openshift.io/csi":              "false",
		"features.operators.openshift.io/disconnected":     "true",
		"features.operators.openshift.io/fips-compliant":   "true",
		"features.operators.openshift.io/proxy-aware":      "false",
		"features.operators.openshift.io/tls-profiles":     "false",
		"features.operators.openshift.io/token-auth-aws":   "false",
		"features.operators.openshift.io/token-auth-azure": "false",
		"features.operators.openshift.io/token-auth-gcp":   "false",
	}

	annotations, ok := csv["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})
	if !ok {
		log.Fatal("Error: 'annotations' does not exist within 'metadata' in the CSV content")
	}

	for key, value := range requiredAnnotations {
		annotations[key] = value
	}
	fmt.Println("Added required annotations")
}

func replaceVersion(oldVersion, newVersion string, csv map[string]interface{}) {
	spec, ok := csv["spec"].(map[string]interface{})
	metadata, ok := csv["metadata"].(map[string]interface{})
	if !ok {
		log.Fatal("Error: 'spec' does not exist in the CSV content")
	}

	fmt.Println(fmt.Sprintf("Updating version references from %s to %s", oldVersion, newVersion))

	spec["version"] = newVersion
	spec["replaces"] = "compliance-operator.v" + oldVersion

	metadata["name"] = strings.Replace(metadata["name"].(string), oldVersion, newVersion, 1)

	annotations := metadata["annotations"].(map[string]interface{})
	annotations["olm.skipRange"] = strings.Replace(annotations["olm.skipRange"].(string), oldVersion, newVersion, 1)

	fmt.Println(fmt.Sprintf("Updated version references from %s to %s", oldVersion, newVersion))
}

func replaceIcon(csv map[string]interface{}) {

	s, ok := csv["spec"]
	if !ok {
		log.Fatal("Error: 'spec' does not exist in the CSV content")
	}
	spec := s.(map[string]interface{})

	iconPath := "../bundle/icons/icon.png"
	iconData, err := os.ReadFile(iconPath)
	if err != nil {
		log.Fatal(fmt.Sprintf("Error: Failed to read icon file '%s'", iconPath))
	}
	icon := make(map[string]string)
	icon["base64data"] = base64.StdEncoding.EncodeToString(iconData)
	icon["media"] = "image/png"

	var icons = make([]map[string]string, 1)
	icons[0] = icon

	spec["icon"] = icons

	fmt.Println(fmt.Sprintf("Updated the operator image to use icon in %s", iconPath))
}

//func recoverFromReplaceImages() {
//	if r := recover(); r != nil {
//		log.Fatal("Error: It was not possible to replace RELATED_IMAGE_OPERATOR")
//	}
//}

func getPullSpecSha(pullSpec string) string {
	delimiter := "@"

	parts := strings.Split(pullSpec, delimiter)
	if len(parts) > 2 {
		log.Fatalf("Error: Failed to safely determine image SHA from Konflux pull spec: %s", pullSpec)
	}
	return parts[1]
}

func replaceImages(csv map[string]interface{}) {
	//	defer recoverFromReplaceImages()

	// Konflux will automatically update the image sha based on the most
	// recent builds. We want to peel off the SHA and append it to the Red
	// Hat registry so that the bundle image will work when it's available
	// there.
	imageShaOperator := getPullSpecSha(konfluxOperatorPullSpec)
	imageShaOpenscap := getPullSpecSha(konfluxOpenscapPullSpec)
	imageShaContent := getPullSpecSha(konfluxContentPullSpec)
	imageShaMustGather := getPullSpecSha(konfluxMustGatherPullSpec)

	env, ok := csv["spec"].(map[string]interface{})["install"].(map[string]interface{})["spec"].(map[string]interface{})["deployments"].([]interface{})[0].(map[string]interface{})["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})["containers"].([]interface{})[0].(map[string]interface{})["env"].([]interface{})
	if !ok {
		log.Fatal("Error: 'env' with RELATED_IMAGE_OPERATOR does not exist in the CSV content")
	}

	delimiter := "@"
	registryPrefix := "registry.redhat.io/compliance/"
	newPullSpecs := map[string]string{
		"RELATED_IMAGE_OPERATOR":    registryPrefix + "openshift-compliance-rhel8-operator" + delimiter + imageShaOperator,
		"RELATED_IMAGE_OPENSCAP":    registryPrefix + "openshift-compliance-openscap-rhel8" + delimiter + imageShaOpenscap,
		"RELATED_IMAGE_PROFILE":     registryPrefix + "openshift-compliance-content-rhel8" + delimiter + imageShaContent,
		"RELATED_IMAGE_MUST_GATHER": registryPrefix + "openshift-compliance-must-gather-rhel8" + delimiter + imageShaMustGather,
	}

	for _, item := range env {
		variable := item.(map[string]interface{})
		variable["value"] = newPullSpecs[variable["name"].(string)]
	}

	// Update the image pull spec
	containersMap := csv["spec"].(map[string]interface{})["install"].(map[string]interface{})["spec"].(map[string]interface{})["deployments"].([]interface{})[0].(map[string]interface{})["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})["containers"].([]interface{})[0].(map[string]interface{})
	containersMap["image"] = newPullSpecs["RELATED_IMAGE_OPERATOR"]

	// Update the must-gather-image annotation
	annotations := csv["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})
	annotations["must-gather-image"] = newPullSpecs["RELATED_IMAGE_MUST_GATHER"]

	// Update the alm-examples
	var almExamplesJson interface{}
	if err := json.Unmarshal([]byte(annotations["alm-examples"].(string)), &almExamplesJson); err != nil {
		log.Fatal("Error: Failed to decode alm-examples")
	}
	for _, item := range almExamplesJson.([]interface{}) {
		if spec, ok := item.(map[string]interface{})["spec"]; ok {
			if _, ok := spec.(map[string]interface{})["contentImage"]; ok {
				spec.(map[string]interface{})["contentImage"] = newPullSpecs["RELATED_IMAGE_OPERATOR"]
			}

			if scans, ok := spec.(map[string]interface{})["scans"]; ok {
				for _, scan := range scans.([]interface{}) {
					if _, ok := scan.(map[string]interface{})["contentImage"]; ok {
						scan.(map[string]interface{})["contentImage"] = newPullSpecs["RELATED_IMAGE_OPERATOR"]
					}
				}
			}
		}

	}

	almExamplesDecoded, _ := json.MarshalIndent(almExamplesJson, "", "  ")
	annotations["alm-examples"] = string(almExamplesDecoded)

	fmt.Println("Updated the deployment manifest to use downstream builds")
}

func updateRelatedImages(csv map[string]interface{}) {
	spec, ok := csv["spec"].(map[string]interface{})
	if !ok {
		log.Fatal("Error: 'spec' does not exist in the CSV content")
	}

	// Extract SHAs from Konflux pull specs and build Red Hat registry URLs
	imageShaOperator := getPullSpecSha(konfluxOperatorPullSpec)
	imageShaOpenscap := getPullSpecSha(konfluxOpenscapPullSpec)
	imageShaContent := getPullSpecSha(konfluxContentPullSpec)
	imageShaMustGather := getPullSpecSha(konfluxMustGatherPullSpec)

	delimiter := "@"
	registryPrefix := "registry.redhat.io/compliance/"

	// Create or update the relatedImages section with Red Hat registry images
	relatedImages := []map[string]string{
		{
			"name":  "openscap",
			"image": registryPrefix + "openshift-compliance-openscap-rhel8" + delimiter + imageShaOpenscap,
		},
		{
			"name":  "operator",
			"image": registryPrefix + "openshift-compliance-rhel8-operator" + delimiter + imageShaOperator,
		},
		{
			"name":  "profile",
			"image": registryPrefix + "openshift-compliance-content-rhel8" + delimiter + imageShaContent,
		},
		{
			"name":  "must-gather",
			"image": registryPrefix + "openshift-compliance-must-gather-rhel8" + delimiter + imageShaMustGather,
		},
	}

	spec["relatedImages"] = relatedImages
	fmt.Println("Updated relatedImages with Red Hat registry images")
}

func main() {
	var csv map[string]interface{}

	manifestsDir := os.Args[1]
	oldVersion := os.Args[2]
	newVersion := os.Args[3]

	csvFilename := getInputCSVFilePath(manifestsDir)
	fmt.Println(fmt.Sprintf("Found manifest in %s", csvFilename))

	readCSV(csvFilename, &csv)

	addRequiredAnnotations(csv)
	replaceVersion(oldVersion, newVersion, csv)
	replaceIcon(csv)
	replaceImages(csv)
	updateRelatedImages(csv)

	outputCSVFilename := getOutputCSVFilePath(manifestsDir, newVersion)
	replaceCSV(csvFilename, outputCSVFilename, csv)
	fmt.Println(fmt.Sprintf("Replaced CSV manifest for %s", newVersion))
}
