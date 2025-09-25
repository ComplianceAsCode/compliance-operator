/*
Copyright © 2025 Red Hat Inc.
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

package fetchers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ComplianceAsCode/compliance-sdk/pkg/scanner"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// ResourceDiscoveryCache caches resource discovery information
type ResourceDiscoveryCache struct {
	mu                  sync.RWMutex
	resourceScope       map[schema.GroupVersionKind]bool             // true if namespaced
	resourceMapping     map[string]metav1.APIResource                // resourceType -> APIResource
	groupVersionMapping map[schema.GroupVersion][]metav1.APIResource // GV -> APIResources
}

var globalResourceDiscoveryCache = &ResourceDiscoveryCache{
	resourceScope:       make(map[schema.GroupVersionKind]bool),
	resourceMapping:     make(map[string]metav1.APIResource),
	groupVersionMapping: make(map[schema.GroupVersion][]metav1.APIResource),
}

// ResourceMappingConfig allows customization of resource mappings
type ResourceMappingConfig struct {
	// CustomKindMappings allows override of resource type to Kind mappings
	CustomKindMappings map[string]string
	// CustomScopeMappings allows override of resource scope (true=namespaced, false=cluster-scoped)
	CustomScopeMappings map[schema.GroupVersionKind]bool
}

// DefaultResourceMappingConfig returns a default configuration
func DefaultResourceMappingConfig() *ResourceMappingConfig {
	return &ResourceMappingConfig{
		CustomKindMappings:  make(map[string]string),
		CustomScopeMappings: make(map[schema.GroupVersionKind]bool),
	}
}

// KubernetesFetcher implements InputFetcher for Kubernetes resources
type KubernetesFetcher struct {
	client          runtimeclient.Client
	clientset       kubernetes.Interface
	discoveryClient discovery.DiscoveryInterface
	apiResourcePath string // Path to pre-fetched API resources (optional)
	config          *ResourceMappingConfig
}

// NewKubernetesFetcher creates a new Kubernetes input fetcher
func NewKubernetesFetcher(client runtimeclient.Client, clientset kubernetes.Interface) *KubernetesFetcher {
	var discoveryClient discovery.DiscoveryInterface
	if clientset != nil {
		discoveryClient = clientset.Discovery()
	}

	return &KubernetesFetcher{
		client:          client,
		clientset:       clientset,
		discoveryClient: discoveryClient,
		config:          DefaultResourceMappingConfig(),
	}
}

// NewKubernetesFileFetcher creates a fetcher that reads from pre-fetched files
func NewKubernetesFileFetcher(apiResourcePath string) *KubernetesFetcher {
	return &KubernetesFetcher{
		apiResourcePath: apiResourcePath,
		config:          DefaultResourceMappingConfig(),
	}
}

// WithConfig allows customization of the fetcher configuration
func (k *KubernetesFetcher) WithConfig(config *ResourceMappingConfig) *KubernetesFetcher {
	k.config = config
	return k
}

// FetchInputs retrieves Kubernetes resources for the specified inputs
func (k *KubernetesFetcher) FetchInputs(inputs []scanner.Input, variables []scanner.CelVariable) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	for _, input := range inputs {
		if input.Type() != scanner.InputTypeKubernetes {
			continue
		}

		kubeSpec, ok := input.Spec().(scanner.KubernetesInputSpec)
		if !ok {
			return nil, fmt.Errorf("invalid Kubernetes input spec for input %s", input.Name())
		}

		data, err := k.fetchKubernetesResource(kubeSpec)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch Kubernetes resource for input %s: %w", input.Name(), err)
		}

		result[input.Name()] = data
	}

	return result, nil
}

// SupportsInputType returns true for Kubernetes input types
func (k *KubernetesFetcher) SupportsInputType(inputType scanner.InputType) bool {
	return inputType == scanner.InputTypeKubernetes
}

// fetchKubernetesResource retrieves a specific Kubernetes resource
func (k *KubernetesFetcher) fetchKubernetesResource(spec scanner.KubernetesInputSpec) (interface{}, error) {
	if k.apiResourcePath != "" {
		// Fetch from pre-cached files
		return k.fetchFromFile(spec)
	}

	if k.client == nil {
		return nil, fmt.Errorf("no Kubernetes client available")
	}

	// Fetch from live API
	return k.fetchFromAPI(spec)
}

// fetchFromFile reads resources from pre-cached files
func (k *KubernetesFetcher) fetchFromFile(spec scanner.KubernetesInputSpec) (interface{}, error) {
	// Build file path based on resource specification
	var filePath string

	// Use API discovery to determine if resource is namespaced, even for file operations
	// This ensures consistent behavior between file and API fetching
	isNamespaced := IsNamespacedWithConfig(spec, k.discoveryClient, k.config)

	if isNamespaced && spec.Namespace() != "" {
		filePath = filepath.Join(k.apiResourcePath, "namespaces", spec.Namespace(), fmt.Sprintf("%s.json", spec.ResourceType()))
	} else {
		filePath = filepath.Join(k.apiResourcePath, fmt.Sprintf("%s.json", spec.ResourceType()))
	}

	// Read and parse the file
	data, err := readJSONFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read resource file %s: %w", filePath, err)
	}

	// Filter by name if specified
	if spec.Name() != "" {
		return filterResourceByName(data, spec.Name())
	}

	return data, nil
}

// fetchFromAPI retrieves resources from the Kubernetes API
func (k *KubernetesFetcher) fetchFromAPI(spec scanner.KubernetesInputSpec) (interface{}, error) {
	ctx := context.Background()

	// Create GVK using dynamic discovery
	gvk := GetGVKWithConfig(spec, k.config, k.discoveryClient)

	// Determine if the resource is namespaced using API discovery
	isNamespaced := IsNamespacedWithConfig(spec, k.discoveryClient, k.config)

	// Create unstructured object
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(gvk)

	if spec.Name() != "" {
		// Fetch specific resource
		key := runtimeclient.ObjectKey{
			Name: spec.Name(),
		}

		// Only set namespace if the resource is actually namespaced
		if isNamespaced && spec.Namespace() != "" {
			key.Namespace = spec.Namespace()
		}

		if err := k.client.Get(ctx, key, obj); err != nil {
			return nil, fmt.Errorf("failed to get resource %s/%s: %w", spec.ResourceType(), spec.Name(), err)
		}

		return obj.Object, nil
	}

	// Fetch list of resources
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(gvk)

	listOpts := &runtimeclient.ListOptions{}

	// Only set namespace if the resource is actually namespaced
	if isNamespaced && spec.Namespace() != "" {
		listOpts.Namespace = spec.Namespace()
	}

	if err := k.client.List(ctx, list, listOpts); err != nil {
		return nil, fmt.Errorf("failed to list resources %s: %w", spec.ResourceType(), err)
	}

	// Convert to the expected format
	result := map[string]interface{}{
		"apiVersion": list.GetAPIVersion(),
		"kind":       list.GetKind(),
		"items":      make([]interface{}, len(list.Items)),
	}

	for i, item := range list.Items {
		result["items"].([]interface{})[i] = item.Object
	}

	return result, nil
}

// Helper functions

func readJSONFile(filePath string) (map[string]interface{}, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON from file %s: %w", filePath, err)
	}

	return result, nil
}

func filterResourceByName(data map[string]interface{}, name string) (interface{}, error) {
	// Extract single resource from list by name
	items, ok := data["items"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid resource data format")
	}

	for _, item := range items {
		if itemMap, ok := item.(map[string]interface{}); ok {
			if metadata, ok := itemMap["metadata"].(map[string]interface{}); ok {
				if resourceName, ok := metadata["name"].(string); ok && resourceName == name {
					return item, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("resource %s not found", name)
}

// KubernetesInputSpec implementation helpers

// ValidateKubernetesInputSpec validates a Kubernetes input specification
func ValidateKubernetesInputSpec(spec scanner.KubernetesInputSpec) error {
	if spec.ResourceType() == "" {
		return fmt.Errorf("resource type is required")
	}

	if spec.Version() == "" {
		return fmt.Errorf("version is required")
	}

	// Add more validation as needed
	return nil
}

// ValidateKubernetesInputSpecWithDiscovery validates a Kubernetes input specification using API discovery
func ValidateKubernetesInputSpecWithDiscovery(spec scanner.KubernetesInputSpec, discoveryClient discovery.DiscoveryInterface) error {
	if err := ValidateKubernetesInputSpec(spec); err != nil {
		return err
	}

	// If we have a discovery client, verify the resource actually exists
	if discoveryClient != nil {
		if err := verifyResourceExists(discoveryClient, spec); err != nil {
			return fmt.Errorf("resource validation failed: %w", err)
		}
	}

	return nil
}

// verifyResourceExists checks if a resource exists in the API server
func verifyResourceExists(discoveryClient discovery.DiscoveryInterface, spec scanner.KubernetesInputSpec) error {
	gvk := GetGVK(spec)
	groupVersion := gvk.GroupVersion().String()

	apiResourceList, err := discoveryClient.ServerResourcesForGroupVersion(groupVersion)
	if err != nil {
		return fmt.Errorf("failed to get API resources for %s: %w", groupVersion, err)
	}

	resourceName := strings.ToLower(gvk.Kind)
	for _, apiResource := range apiResourceList.APIResources {
		if apiResource.Kind == gvk.Kind ||
			apiResource.Name == resourceName ||
			apiResource.SingularName == resourceName {
			return nil // Resource exists
		}
	}

	return fmt.Errorf("resource %s not found in API group %s", gvk.Kind, groupVersion)
}

// GetResourceScope returns the scope of a resource (namespaced or cluster-scoped) using API discovery
func (k *KubernetesFetcher) GetResourceScope(spec scanner.KubernetesInputSpec) bool {
	return IsNamespacedWithConfig(spec, k.discoveryClient, k.config)
}

// ValidateInputSpec validates a Kubernetes input specification using the fetcher's discovery client
func (k *KubernetesFetcher) ValidateInputSpec(spec scanner.KubernetesInputSpec) error {
	return ValidateKubernetesInputSpecWithDiscovery(spec, k.discoveryClient)
}

// GetGVK returns the GroupVersionKind for a Kubernetes input spec using dynamic discovery
func GetGVK(spec scanner.KubernetesInputSpec) schema.GroupVersionKind {
	return GetGVKWithConfig(spec, DefaultResourceMappingConfig(), nil)
}

// GetGVKWithConfig returns the GroupVersionKind using configuration and discovery
func GetGVKWithConfig(spec scanner.KubernetesInputSpec, config *ResourceMappingConfig, discoveryClient discovery.DiscoveryInterface) schema.GroupVersionKind {
	gv := schema.GroupVersion{
		Group:   spec.ApiGroup(),
		Version: spec.Version(),
	}

	// Try to get Kind from API discovery first
	if discoveryClient != nil {
		if kind := discoverResourceKind(discoveryClient, gv, spec.ResourceType()); kind != "" {
			return schema.GroupVersionKind{
				Group:   spec.ApiGroup(),
				Version: spec.Version(),
				Kind:    kind,
			}
		}
	}

	// Check custom mappings
	if config != nil && config.CustomKindMappings != nil {
		if kind, exists := config.CustomKindMappings[strings.ToLower(spec.ResourceType())]; exists {
			return schema.GroupVersionKind{
				Group:   spec.ApiGroup(),
				Version: spec.Version(),
				Kind:    kind,
			}
		}
	}

	// Fall back to cached mapping or intelligent conversion
	return schema.GroupVersionKind{
		Group:   spec.ApiGroup(),
		Version: spec.Version(),
		Kind:    resourceTypeToKindDynamic(spec.ResourceType(), discoveryClient, gv),
	}
}

// discoverResourceKind discovers the Kind for a resource type using API discovery
func discoverResourceKind(discoveryClient discovery.DiscoveryInterface, gv schema.GroupVersion, resourceType string) string {
	// Check cache first
	globalResourceDiscoveryCache.mu.RLock()
	if resources, exists := globalResourceDiscoveryCache.groupVersionMapping[gv]; exists {
		globalResourceDiscoveryCache.mu.RUnlock()
		return findKindInResources(resources, resourceType)
	}
	globalResourceDiscoveryCache.mu.RUnlock()

	// Discover from API
	groupVersion := gv.String()
	apiResourceList, err := discoveryClient.ServerResourcesForGroupVersion(groupVersion)
	if err != nil {
		return "" // Let caller handle fallback
	}

	// Cache the results
	globalResourceDiscoveryCache.mu.Lock()
	globalResourceDiscoveryCache.groupVersionMapping[gv] = apiResourceList.APIResources

	// Also cache individual resource mappings
	for _, resource := range apiResourceList.APIResources {
		key := fmt.Sprintf("%s/%s", gv.String(), resource.Name)
		globalResourceDiscoveryCache.resourceMapping[key] = resource
	}
	globalResourceDiscoveryCache.mu.Unlock()

	return findKindInResources(apiResourceList.APIResources, resourceType)
}

// findKindInResources finds the Kind for a resource type in API resources
func findKindInResources(resources []metav1.APIResource, resourceType string) string {
	resourceTypeLower := strings.ToLower(resourceType)

	for _, resource := range resources {
		if strings.ToLower(resource.Name) == resourceTypeLower ||
			strings.ToLower(resource.SingularName) == resourceTypeLower ||
			strings.ToLower(resource.Kind) == resourceTypeLower {
			return resource.Kind
		}
	}

	return ""
}

// resourceTypeToKindDynamic converts resource type to Kind with dynamic discovery
func resourceTypeToKindDynamic(resourceType string, discoveryClient discovery.DiscoveryInterface, gv schema.GroupVersion) string {
	// Try discovery first
	if discoveryClient != nil {
		if kind := discoverResourceKind(discoveryClient, gv, resourceType); kind != "" {
			return kind
		}
	}

	// Fall back to intelligent conversion
	return toPascalCase(resourceType)
}

// IsNamespaced returns true if the resource is namespaced using dynamic discovery
func IsNamespaced(spec scanner.KubernetesInputSpec) bool {
	return IsNamespacedWithConfig(spec, nil, DefaultResourceMappingConfig())
}

// IsNamespacedWithDiscovery returns true if the resource is namespaced using API discovery
func IsNamespacedWithDiscovery(spec scanner.KubernetesInputSpec, discoveryClient discovery.DiscoveryInterface) bool {
	return IsNamespacedWithConfig(spec, discoveryClient, DefaultResourceMappingConfig())
}

// IsNamespacedWithConfig returns true if the resource is namespaced using configuration and discovery
func IsNamespacedWithConfig(spec scanner.KubernetesInputSpec, discoveryClient discovery.DiscoveryInterface, config *ResourceMappingConfig) bool {
	gvk := GetGVKWithConfig(spec, config, discoveryClient)

	// Check custom scope mappings first
	if config != nil && config.CustomScopeMappings != nil {
		if namespaced, exists := config.CustomScopeMappings[gvk]; exists {
			cacheResourceScope(gvk, namespaced)
			return namespaced
		}
	}

	// Check cache
	globalResourceDiscoveryCache.mu.RLock()
	if namespaced, exists := globalResourceDiscoveryCache.resourceScope[gvk]; exists {
		globalResourceDiscoveryCache.mu.RUnlock()
		return namespaced
	}
	globalResourceDiscoveryCache.mu.RUnlock()

	// Use API discovery
	if discoveryClient != nil {
		namespaced := discoverResourceScopeDynamic(discoveryClient, gvk)
		if namespaced != nil {
			cacheResourceScope(gvk, *namespaced)
			return *namespaced
		}
	}

	// Default to namespaced for unknown resources
	cacheResourceScope(gvk, true)
	return true
}

// discoverResourceScopeDynamic uses API discovery to determine if a resource is namespaced
func discoverResourceScopeDynamic(discoveryClient discovery.DiscoveryInterface, gvk schema.GroupVersionKind) *bool {
	groupVersion := gvk.GroupVersion().String()

	// Check cache first
	globalResourceDiscoveryCache.mu.RLock()
	if resources, exists := globalResourceDiscoveryCache.groupVersionMapping[gvk.GroupVersion()]; exists {
		globalResourceDiscoveryCache.mu.RUnlock()
		for _, resource := range resources {
			if resource.Kind == gvk.Kind {
				return &resource.Namespaced
			}
		}
		return nil
	}
	globalResourceDiscoveryCache.mu.RUnlock()

	// Discover from API
	apiResourceList, err := discoveryClient.ServerResourcesForGroupVersion(groupVersion)
	if err != nil {
		return nil
	}

	// Cache the results
	globalResourceDiscoveryCache.mu.Lock()
	globalResourceDiscoveryCache.groupVersionMapping[gvk.GroupVersion()] = apiResourceList.APIResources
	globalResourceDiscoveryCache.mu.Unlock()

	// Find the specific resource
	for _, apiResource := range apiResourceList.APIResources {
		if apiResource.Kind == gvk.Kind {
			return &apiResource.Namespaced
		}
	}

	return nil
}

// cacheResourceScope caches the resource scope information
func cacheResourceScope(gvk schema.GroupVersionKind, namespaced bool) {
	globalResourceDiscoveryCache.mu.Lock()
	defer globalResourceDiscoveryCache.mu.Unlock()
	globalResourceDiscoveryCache.resourceScope[gvk] = namespaced
}

// toPascalCase converts a string to PascalCase
func toPascalCase(s string) string {
	if s == "" {
		return s
	}

	// Split by common delimiters
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '-' || r == '_' || r == '.' || r == ' '
	})

	if len(parts) == 0 {
		return strings.Title(s)
	}

	result := ""
	for _, part := range parts {
		if part != "" {
			result += strings.Title(strings.ToLower(part))
		}
	}

	if result == "" {
		return strings.Title(s)
	}

	return result
}

// ClearDiscoveryCache clears the discovery cache (useful for testing)
func ClearDiscoveryCache() {
	globalResourceDiscoveryCache.mu.Lock()
	defer globalResourceDiscoveryCache.mu.Unlock()

	globalResourceDiscoveryCache.resourceScope = make(map[schema.GroupVersionKind]bool)
	globalResourceDiscoveryCache.resourceMapping = make(map[string]metav1.APIResource)
	globalResourceDiscoveryCache.groupVersionMapping = make(map[schema.GroupVersion][]metav1.APIResource)
}

// LoadResourceMappingsFromFile loads custom resource mappings from a JSON file
func LoadResourceMappingsFromFile(filePath string) (*ResourceMappingConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read resource mappings file: %w", err)
	}

	var config ResourceMappingConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal resource mappings: %w", err)
	}

	// Set defaults if not specified
	if config.CustomKindMappings == nil {
		config.CustomKindMappings = make(map[string]string)
	}
	if config.CustomScopeMappings == nil {
		config.CustomScopeMappings = make(map[schema.GroupVersionKind]bool)
	}

	return &config, nil
}
