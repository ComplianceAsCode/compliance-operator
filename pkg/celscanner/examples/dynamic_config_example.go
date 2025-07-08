/*
Copyright © 2024 Red Hat Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package examples

import (
	"fmt"

	"github.com/ComplianceAsCode/compliance-operator/pkg/celscanner/inputs"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ExampleDynamicConfiguration demonstrates how to configure the fetcher for different scenarios
func ExampleDynamicConfiguration() {
	// Example 1: Default configuration (primarily uses API discovery)
	defaultConfig := inputs.DefaultResourceMappingConfig()
	fmt.Printf("Default config initialized: %v\n", defaultConfig != nil)

	// Example 2: API discovery only (minimal configuration)
	apiOnlyConfig := &inputs.ResourceMappingConfig{
		CustomKindMappings:  make(map[string]string),
		CustomScopeMappings: make(map[schema.GroupVersionKind]bool),
	}

	// Example 3: Custom mappings for special cases
	customConfig := &inputs.ResourceMappingConfig{
		CustomKindMappings: map[string]string{
			"myresource":    "MyCustomResource",
			"specialpod":    "Pod", // Map special aliases
			"legacyservice": "Service",
		},
		CustomScopeMappings: map[schema.GroupVersionKind]bool{
			// Override specific resources
			{Group: "custom.io", Version: "v1", Kind: "MyResource"}:       false, // cluster-scoped
			{Group: "legacy.io", Version: "v1beta1", Kind: "OldResource"}: true,  // namespaced
		},
	}

	// Example 4: Pre-configured environment (all mappings defined)
	preconfiguredConfig := &inputs.ResourceMappingConfig{
		CustomKindMappings: map[string]string{
			// Define all your mappings upfront
			"pods":                   "Pod",
			"services":               "Service",
			"deployments":            "Deployment",
			"configmaps":             "ConfigMap",
			"secrets":                "Secret",
			"persistentvolumes":      "PersistentVolume",
			"persistentvolumeclaims": "PersistentVolumeClaim",
			"nodes":                  "Node",
			"namespaces":             "Namespace",
			"clusterroles":           "ClusterRole",
			"clusterrolebindings":    "ClusterRoleBinding",
		},
		CustomScopeMappings: map[schema.GroupVersionKind]bool{
			// Define scopes for all resources you'll use
			{Group: "", Version: "v1", Kind: "Pod"}:                                         true,  // namespaced
			{Group: "", Version: "v1", Kind: "Service"}:                                     true,  // namespaced
			{Group: "apps", Version: "v1", Kind: "Deployment"}:                              true,  // namespaced
			{Group: "", Version: "v1", Kind: "ConfigMap"}:                                   true,  // namespaced
			{Group: "", Version: "v1", Kind: "Secret"}:                                      true,  // namespaced
			{Group: "", Version: "v1", Kind: "PersistentVolume"}:                            false, // cluster-scoped
			{Group: "", Version: "v1", Kind: "PersistentVolumeClaim"}:                       true,  // namespaced
			{Group: "", Version: "v1", Kind: "Node"}:                                        false, // cluster-scoped
			{Group: "", Version: "v1", Kind: "Namespace"}:                                   false, // cluster-scoped
			{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRole"}:        false, // cluster-scoped
			{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRoleBinding"}: false, // cluster-scoped
		},
	}

	// Usage examples
	fmt.Println("\n=== Configuration Examples ===")

	fmt.Printf("API-only config: %+v\n", apiOnlyConfig)
	fmt.Printf("Custom config has %d kind mappings\n", len(customConfig.CustomKindMappings))
	fmt.Printf("Pre-configured config has %d scope mappings\n", len(preconfiguredConfig.CustomScopeMappings))
}

// ExampleLoadFromFile demonstrates loading configuration from file
func ExampleLoadFromFile() {
	// This would load from a JSON file like:
	// {
	//   "customKindMappings": {
	//     "myresource": "MyCustomResource"
	//   },
	//   "customScopeMappings": {
	//     "custom.io/v1/MyResource": false
	//   }
	// }

	configPath := "/etc/compliance/resource-mappings.json"
	config, err := inputs.LoadResourceMappingsFromFile(configPath)
	if err != nil {
		fmt.Printf("Could not load config from %s: %v\n", configPath, err)
		// Use default config as fallback
		config = inputs.DefaultResourceMappingConfig()
	}

	fmt.Printf("Loaded config with %d custom mappings\n", len(config.CustomKindMappings))
}

// ExampleConfigureFetcher shows how to configure a fetcher with custom settings
func ExampleConfigureFetcher() {
	// Create a custom configuration
	config := &inputs.ResourceMappingConfig{
		CustomKindMappings: map[string]string{
			"scc": "SecurityContextConstraints", // OpenShift SCC shorthand
		},
		CustomScopeMappings: map[schema.GroupVersionKind]bool{
			{Group: "security.openshift.io", Version: "v1", Kind: "SecurityContextConstraints"}: false,
		},
	}

	// Create fetcher and apply configuration
	fetcher := inputs.NewKubernetesFetcher(nil, nil).WithConfig(config)

	// Now the fetcher will use your custom configuration
	fmt.Printf("Fetcher configured with custom mappings: %v\n", fetcher != nil)
}

// ExampleRuntimeDiscovery shows how the system works with live API discovery
func ExampleRuntimeDiscovery() {
	// When connected to a live cluster, the system will:

	// 1. First try API discovery to get the real Kind and scope
	// 2. Cache the results for performance
	// 3. Fall back to custom mappings if discovery fails
	// 4. Use intelligent conversion for unknown resources

	fmt.Println("Runtime discovery flow:")
	fmt.Println("1. API Discovery (live cluster)")
	fmt.Println("2. Custom mappings (config)")
	fmt.Println("3. Intelligent conversion (PascalCase)")
	fmt.Println("4. Default to namespaced for unknown resources")
}

// ExampleEnvironmentSpecificConfigs shows different configs for different environments
func ExampleEnvironmentSpecificConfigs() {
	// Development: Minimal configuration, rely on API discovery
	devConfig := inputs.DefaultResourceMappingConfig()

	// Production: Explicit mappings for all resources
	prodConfig := &inputs.ResourceMappingConfig{
		CustomKindMappings: map[string]string{
			// Only known, tested mappings
			"pods":     "Pod",
			"services": "Service",
			// ... add all production resources
		},
		CustomScopeMappings: map[schema.GroupVersionKind]bool{
			// Explicitly define all resource scopes
			{Group: "", Version: "v1", Kind: "Pod"}:     true,
			{Group: "", Version: "v1", Kind: "Service"}: true,
			// ... add all production resources
		},
	}

	// Air-gapped: Everything predefined, no API discovery available
	airgappedConfig := &inputs.ResourceMappingConfig{
		CustomKindMappings: map[string]string{
			// Complete list of all resources you need
			"pods":                   "Pod",
			"services":               "Service",
			"deployments":            "Deployment",
			"configmaps":             "ConfigMap",
			"secrets":                "Secret",
			"persistentvolumes":      "PersistentVolume",
			"persistentvolumeclaims": "PersistentVolumeClaim",
			"nodes":                  "Node",
			"namespaces":             "Namespace",
		},
		CustomScopeMappings: map[schema.GroupVersionKind]bool{
			// Complete list of all resource scopes
			{Group: "", Version: "v1", Kind: "Pod"}:                   true,
			{Group: "", Version: "v1", Kind: "Service"}:               true,
			{Group: "apps", Version: "v1", Kind: "Deployment"}:        true,
			{Group: "", Version: "v1", Kind: "ConfigMap"}:             true,
			{Group: "", Version: "v1", Kind: "Secret"}:                true,
			{Group: "", Version: "v1", Kind: "PersistentVolume"}:      false,
			{Group: "", Version: "v1", Kind: "PersistentVolumeClaim"}: true,
			{Group: "", Version: "v1", Kind: "Node"}:                  false,
			{Group: "", Version: "v1", Kind: "Namespace"}:             false,
		},
	}

	fmt.Printf("Dev config has %d kind mappings\n", len(devConfig.CustomKindMappings))
	fmt.Printf("Prod config has %d kind mappings\n", len(prodConfig.CustomKindMappings))
	fmt.Printf("Air-gapped config has %d scope mappings\n", len(airgappedConfig.CustomScopeMappings))
}

// Example showing the difference between old hard-coded vs new dynamic approach
func ExampleOldVsNewApproach() {
	fmt.Println("=== OLD APPROACH (Hard-coded) ===")
	fmt.Println("❌ Fixed list of 40+ resource mappings")
	fmt.Println("❌ Fixed list of 80+ scope definitions")
	fmt.Println("❌ Fixed API group logic")
	fmt.Println("❌ No customization possible")
	fmt.Println("❌ Requires code changes for new resources")

	fmt.Println("\n=== NEW APPROACH (Dynamic) ===")
	fmt.Println("✅ API discovery for real-time resource info")
	fmt.Println("✅ Configurable custom mappings")
	fmt.Println("✅ Runtime caching for performance")
	fmt.Println("✅ Environment-specific configurations")
	fmt.Println("✅ Intelligent fallbacks")
	fmt.Println("✅ No code changes needed for new resources")

	fmt.Println("\n=== MIGRATION PATH ===")
	fmt.Println("1. Use DefaultResourceMappingConfig() for backward compatibility")
	fmt.Println("2. Gradually add custom mappings for your specific resources")
	fmt.Println("3. Consider explicit mappings in production environments")
	fmt.Println("4. Use LoadResourceMappingsFromFile() for external configuration")
}
