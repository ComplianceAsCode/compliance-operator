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

package inputs

import (
	"testing"

	"github.com/ComplianceAsCode/compliance-operator/pkg/celscanner"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// mockKubernetesInputSpec implements KubernetesInputSpec for testing
type mockKubernetesInputSpec struct {
	apiGroup     string
	version      string
	resourceType string
	namespace    string
	name         string
}

func (m *mockKubernetesInputSpec) ApiGroup() string     { return m.apiGroup }
func (m *mockKubernetesInputSpec) Version() string      { return m.version }
func (m *mockKubernetesInputSpec) ResourceType() string { return m.resourceType }
func (m *mockKubernetesInputSpec) Namespace() string    { return m.namespace }
func (m *mockKubernetesInputSpec) Name() string         { return m.name }
func (m *mockKubernetesInputSpec) Validate() error      { return nil }

func TestIsNamespacedWithDynamicDiscovery(t *testing.T) {
	// Clear cache before testing
	ClearDiscoveryCache()

	testCases := []struct {
		name        string
		spec        celscanner.KubernetesInputSpec
		config      *ResourceMappingConfig
		expected    bool
		description string
	}{
		{
			name: "Pod - namespaced (default config)",
			spec: &mockKubernetesInputSpec{
				apiGroup:     "",
				version:      "v1",
				resourceType: "pod",
				namespace:    "default",
				name:         "test-pod",
			},
			config:      DefaultResourceMappingConfig(),
			expected:    true,
			description: "Pods are namespaced resources",
		},
		{
			name: "Node - with custom scope mapping",
			spec: &mockKubernetesInputSpec{
				apiGroup:     "",
				version:      "v1",
				resourceType: "node",
				namespace:    "",
				name:         "test-node",
			},
			config: &ResourceMappingConfig{
				CustomKindMappings: make(map[string]string),
				CustomScopeMappings: map[schema.GroupVersionKind]bool{
					{Group: "", Version: "v1", Kind: "Node"}: false, // cluster-scoped
				},
			},
			expected:    false,
			description: "Nodes are cluster-scoped when explicitly configured",
		},
		{
			name: "Custom resource - override with config",
			spec: &mockKubernetesInputSpec{
				apiGroup:     "custom.io",
				version:      "v1",
				resourceType: "myresource",
				namespace:    "",
				name:         "test-custom",
			},
			config: &ResourceMappingConfig{
				CustomKindMappings: map[string]string{
					"myresource": "MyCustomResource",
				},
				CustomScopeMappings: map[schema.GroupVersionKind]bool{
					{Group: "custom.io", Version: "v1", Kind: "MyCustomResource"}: false, // cluster-scoped
				},
			},
			expected:    false,
			description: "Custom resource should use configured scope",
		},
		{
			name: "Unknown resource - default to namespaced",
			spec: &mockKubernetesInputSpec{
				apiGroup:     "unknown.io",
				version:      "v1",
				resourceType: "unknownresource",
				namespace:    "default",
				name:         "test-unknown",
			},
			config: &ResourceMappingConfig{
				CustomKindMappings:  make(map[string]string),
				CustomScopeMappings: make(map[schema.GroupVersionKind]bool),
			},
			expected:    true,
			description: "Unknown resources default to namespaced",
		},
		{
			name: "SecurityContextConstraints - with custom scope mapping",
			spec: &mockKubernetesInputSpec{
				apiGroup:     "security.openshift.io",
				version:      "v1",
				resourceType: "securitycontextconstraints",
				namespace:    "",
				name:         "test-scc",
			},
			config: &ResourceMappingConfig{
				CustomKindMappings: make(map[string]string),
				CustomScopeMappings: map[schema.GroupVersionKind]bool{
					{Group: "security.openshift.io", Version: "v1", Kind: "Securitycontextconstraints"}: false, // cluster-scoped
				},
			},
			expected:    false,
			description: "SecurityContextConstraints are cluster-scoped when explicitly configured",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsNamespacedWithConfig(tc.spec, nil, tc.config)
			if result != tc.expected {
				t.Errorf("Test %s failed: expected %v, got %v. %s", tc.name, tc.expected, result, tc.description)
			}
		})
	}
}

func TestGetGVKWithDynamicDiscovery(t *testing.T) {
	testCases := []struct {
		name     string
		spec     celscanner.KubernetesInputSpec
		config   *ResourceMappingConfig
		expected schema.GroupVersionKind
	}{
		{
			name: "Core API group with default config",
			spec: &mockKubernetesInputSpec{
				apiGroup:     "",
				version:      "v1",
				resourceType: "pod",
			},
			config: DefaultResourceMappingConfig(),
			expected: schema.GroupVersionKind{
				Group:   "",
				Version: "v1",
				Kind:    "Pod",
			},
		},
		{
			name: "Custom mapping override",
			spec: &mockKubernetesInputSpec{
				apiGroup:     "security.openshift.io",
				version:      "v1",
				resourceType: "scc",
			},
			config: &ResourceMappingConfig{
				CustomKindMappings: map[string]string{
					"scc": "SecurityContextConstraints",
				},
				CustomScopeMappings: make(map[schema.GroupVersionKind]bool),
			},
			expected: schema.GroupVersionKind{
				Group:   "security.openshift.io",
				Version: "v1",
				Kind:    "SecurityContextConstraints",
			},
		},
		{
			name: "Intelligent PascalCase conversion",
			spec: &mockKubernetesInputSpec{
				apiGroup:     "custom.io",
				version:      "v1",
				resourceType: "my-custom-resource",
			},
			config: DefaultResourceMappingConfig(),
			expected: schema.GroupVersionKind{
				Group:   "custom.io",
				Version: "v1",
				Kind:    "MyCustomResource",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := GetGVKWithConfig(tc.spec, tc.config, nil)
			if result != tc.expected {
				t.Errorf("Test %s failed: expected %v, got %v", tc.name, tc.expected, result)
			}
		})
	}
}

func TestValidateKubernetesInputSpec(t *testing.T) {
	testCases := []struct {
		name        string
		spec        celscanner.KubernetesInputSpec
		shouldError bool
		description string
	}{
		{
			name: "Valid spec",
			spec: &mockKubernetesInputSpec{
				apiGroup:     "",
				version:      "v1",
				resourceType: "pod",
				namespace:    "default",
				name:         "test-pod",
			},
			shouldError: false,
			description: "Valid spec should not error",
		},
		{
			name: "Missing resource type",
			spec: &mockKubernetesInputSpec{
				apiGroup:     "",
				version:      "v1",
				resourceType: "",
				namespace:    "default",
				name:         "test-pod",
			},
			shouldError: true,
			description: "Missing resource type should error",
		},
		{
			name: "Missing version",
			spec: &mockKubernetesInputSpec{
				apiGroup:     "",
				version:      "",
				resourceType: "pod",
				namespace:    "default",
				name:         "test-pod",
			},
			shouldError: true,
			description: "Missing version should error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateKubernetesInputSpec(tc.spec)
			if tc.shouldError && err == nil {
				t.Errorf("Test %s failed: expected error but got none. %s", tc.name, tc.description)
			}
			if !tc.shouldError && err != nil {
				t.Errorf("Test %s failed: expected no error but got %v. %s", tc.name, err, tc.description)
			}
		})
	}
}

func TestResourceDiscoveryCache(t *testing.T) {
	// Clear the cache before testing
	ClearDiscoveryCache()

	gvk := schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "Pod",
	}

	// Test caching
	cacheResourceScope(gvk, true)

	// Check if cached value is returned
	globalResourceDiscoveryCache.mu.RLock()
	cached, exists := globalResourceDiscoveryCache.resourceScope[gvk]
	globalResourceDiscoveryCache.mu.RUnlock()

	if !exists {
		t.Error("Expected resource scope to be cached")
	}

	if !cached {
		t.Error("Expected cached value to be true")
	}

	// Test cache clearing
	ClearDiscoveryCache()

	globalResourceDiscoveryCache.mu.RLock()
	_, exists = globalResourceDiscoveryCache.resourceScope[gvk]
	globalResourceDiscoveryCache.mu.RUnlock()

	if exists {
		t.Error("Expected cache to be cleared")
	}
}

func TestToPascalCase(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"pod", "Pod"},
		{"persistent-volume", "PersistentVolume"},
		{"security_context_constraints", "SecurityContextConstraints"},
		{"my.custom.resource", "MyCustomResource"},
		{"already-Pascal-Case", "AlreadyPascalCase"},
		{"", ""},
		{"single", "Single"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := toPascalCase(tc.input)
			if result != tc.expected {
				t.Errorf("toPascalCase(%q) = %q, expected %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestResourceMappingConfig(t *testing.T) {
	t.Run("Default config", func(t *testing.T) {
		config := DefaultResourceMappingConfig()
		if config == nil {
			t.Error("DefaultResourceMappingConfig() returned nil")
		}
		if config.CustomKindMappings == nil {
			t.Error("Expected CustomKindMappings to be initialized")
		}
		if config.CustomScopeMappings == nil {
			t.Error("Expected CustomScopeMappings to be initialized")
		}
	})

	t.Run("Custom config", func(t *testing.T) {
		config := &ResourceMappingConfig{
			CustomKindMappings: map[string]string{
				"test": "Test",
			},
			CustomScopeMappings: map[schema.GroupVersionKind]bool{
				{Group: "test", Version: "v1", Kind: "Test"}: true,
			},
		}

		if len(config.CustomKindMappings) != 1 {
			t.Error("Expected one custom kind mapping")
		}
		if len(config.CustomScopeMappings) != 1 {
			t.Error("Expected one custom scope mapping")
		}
	})
}

func TestWithConfig(t *testing.T) {
	config := &ResourceMappingConfig{
		CustomKindMappings:  make(map[string]string),
		CustomScopeMappings: make(map[schema.GroupVersionKind]bool),
	}

	fetcher := NewKubernetesFetcher(nil, nil).WithConfig(config)

	if fetcher.config != config {
		t.Error("Expected fetcher to use the provided config")
	}
}
