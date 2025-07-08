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
	"context"
	"fmt"
	"time"

	"github.com/ComplianceAsCode/compliance-operator/pkg/celscanner"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// simpleCelVariable implements CelVariable interface for conversion
type simpleCelVariable struct {
	name      string
	namespace string
	value     string
	gvk       schema.GroupVersionKind
}

func (v *simpleCelVariable) Name() string                              { return v.name }
func (v *simpleCelVariable) Namespace() string                         { return v.namespace }
func (v *simpleCelVariable) Value() string                             { return v.value }
func (v *simpleCelVariable) GroupVersionKind() schema.GroupVersionKind { return v.gvk }

// CompositeFetcher implements InputFetcher by delegating to specialized fetchers
type CompositeFetcher struct {
	kubernetesFetcher *KubernetesFetcher
	filesystemFetcher *FilesystemFetcher
	systemFetcher     *SystemFetcher

	// Registry of custom fetchers for extensibility
	customFetchers map[celscanner.InputType]celscanner.InputFetcher
}

// NewCompositeFetcher creates a new composite input fetcher with default implementations
func NewCompositeFetcher() *CompositeFetcher {
	return &CompositeFetcher{
		customFetchers: make(map[celscanner.InputType]celscanner.InputFetcher),
	}
}

// NewCompositeFetcherWithDefaults creates a composite fetcher with default implementations
func NewCompositeFetcherWithDefaults(
	kubeClient runtimeclient.Client,
	kubeClientset kubernetes.Interface,
	apiResourcePath string,
	filesystemBasePath string,
	allowArbitraryCommands bool,
) *CompositeFetcher {
	fetcher := NewCompositeFetcher()

	// Set up Kubernetes fetcher
	if kubeClient != nil && kubeClientset != nil {
		fetcher.kubernetesFetcher = NewKubernetesFetcher(kubeClient, kubeClientset)
	} else if apiResourcePath != "" {
		fetcher.kubernetesFetcher = NewKubernetesFileFetcher(apiResourcePath)
	}

	// Set up filesystem fetcher
	fetcher.filesystemFetcher = NewFilesystemFetcher(filesystemBasePath)

	// Set up system fetcher
	fetcher.systemFetcher = NewSystemFetcher(30*time.Second, allowArbitraryCommands)

	return fetcher
}

// FetchResources implements the ResourceFetcher interface for backwards compatibility
func (c *CompositeFetcher) FetchResources(ctx context.Context, rule celscanner.Rule, variables []celscanner.Variable) (map[string]interface{}, []string, error) {
	// Convert old interfaces to new interfaces
	inputs := rule.GetInputs()
	celInputs := make([]celscanner.Input, len(inputs))
	for i, input := range inputs {
		// Convert RuleInput to Input
		kubeRes := input.GetKubeResource()
		celInputs[i] = celscanner.NewKubernetesInput(
			input.GetName(),
			kubeRes.GetAPIGroup(),
			kubeRes.GetVersion(),
			kubeRes.GetResource(),
			kubeRes.GetNamespace(),
			kubeRes.GetName(),
		)
	}

	// Convert Variables to CelVariables
	celVars := make([]celscanner.CelVariable, len(variables))
	for i, variable := range variables {
		celVars[i] = &simpleCelVariable{
			name:      variable.GetName(),
			namespace: variable.GetNamespace(),
			value:     variable.GetValue(),
			gvk:       variable.GetGroupVersionKind(),
		}
	}

	data, err := c.FetchInputs(celInputs, celVars)
	if err != nil {
		return nil, nil, err
	}

	return data, nil, nil
}

// FetchInputs retrieves inputs by delegating to appropriate specialized fetchers
func (c *CompositeFetcher) FetchInputs(inputs []celscanner.Input, variables []celscanner.CelVariable) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// Group inputs by type
	inputsByType := make(map[celscanner.InputType][]celscanner.Input)
	for _, input := range inputs {
		inputsByType[input.Type()] = append(inputsByType[input.Type()], input)
	}

	// Process each input type
	for inputType, typeInputs := range inputsByType {
		fetcher := c.getFetcherForType(inputType)
		if fetcher == nil {
			return nil, fmt.Errorf("no fetcher available for input type: %s", inputType)
		}

		data, err := fetcher.FetchInputs(typeInputs, variables)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch inputs for type %s: %w", inputType, err)
		}

		// Merge results
		for key, value := range data {
			result[key] = value
		}
	}

	return result, nil
}

// SupportsInputType returns true if any registered fetcher supports the input type
func (c *CompositeFetcher) SupportsInputType(inputType celscanner.InputType) bool {
	return c.getFetcherForType(inputType) != nil
}

// getFetcherForType returns the appropriate fetcher for the input type
func (c *CompositeFetcher) getFetcherForType(inputType celscanner.InputType) celscanner.InputFetcher {
	// Check custom fetchers first
	if fetcher, exists := c.customFetchers[inputType]; exists {
		return fetcher
	}

	// Check built-in fetchers
	switch inputType {
	case celscanner.InputTypeKubernetes:
		return c.kubernetesFetcher
	case celscanner.InputTypeFile:
		return c.filesystemFetcher
	case celscanner.InputTypeSystem:
		return c.systemFetcher
	default:
		return nil
	}
}

// RegisterCustomFetcher registers a custom fetcher for a specific input type
func (c *CompositeFetcher) RegisterCustomFetcher(inputType celscanner.InputType, fetcher celscanner.InputFetcher) {
	c.customFetchers[inputType] = fetcher
}

// SetKubernetesFetcher sets the Kubernetes fetcher
func (c *CompositeFetcher) SetKubernetesFetcher(fetcher *KubernetesFetcher) {
	c.kubernetesFetcher = fetcher
}

// SetFilesystemFetcher sets the filesystem fetcher
func (c *CompositeFetcher) SetFilesystemFetcher(fetcher *FilesystemFetcher) {
	c.filesystemFetcher = fetcher
}

// SetSystemFetcher sets the system fetcher
func (c *CompositeFetcher) SetSystemFetcher(fetcher *SystemFetcher) {
	c.systemFetcher = fetcher
}

// GetSupportedInputTypes returns all supported input types
func (c *CompositeFetcher) GetSupportedInputTypes() []celscanner.InputType {
	var types []celscanner.InputType

	// Add built-in types
	if c.kubernetesFetcher != nil {
		types = append(types, celscanner.InputTypeKubernetes)
	}
	if c.filesystemFetcher != nil {
		types = append(types, celscanner.InputTypeFile)
	}
	if c.systemFetcher != nil {
		types = append(types, celscanner.InputTypeSystem)
	}

	// Add custom types
	for inputType := range c.customFetchers {
		types = append(types, inputType)
	}

	return types
}

// ValidateInputs validates all inputs are supported
func (c *CompositeFetcher) ValidateInputs(inputs []celscanner.Input) error {
	for _, input := range inputs {
		if !c.SupportsInputType(input.Type()) {
			return fmt.Errorf("unsupported input type: %s for input: %s", input.Type(), input.Name())
		}

		// Validate input spec
		if err := input.Spec().Validate(); err != nil {
			return fmt.Errorf("invalid input spec for %s: %w", input.Name(), err)
		}
	}

	return nil
}

// Builder pattern for easy configuration

// CompositeFetcherBuilder helps build composite fetchers
type CompositeFetcherBuilder struct {
	fetcher *CompositeFetcher
}

// NewCompositeFetcherBuilder creates a new builder
func NewCompositeFetcherBuilder() *CompositeFetcherBuilder {
	return &CompositeFetcherBuilder{
		fetcher: NewCompositeFetcher(),
	}
}

// WithKubernetes configures Kubernetes support
func (b *CompositeFetcherBuilder) WithKubernetes(client runtimeclient.Client, clientset kubernetes.Interface) *CompositeFetcherBuilder {
	b.fetcher.SetKubernetesFetcher(NewKubernetesFetcher(client, clientset))
	return b
}

// WithKubernetesFiles configures Kubernetes support with file-based resources
func (b *CompositeFetcherBuilder) WithKubernetesFiles(apiResourcePath string) *CompositeFetcherBuilder {
	b.fetcher.SetKubernetesFetcher(NewKubernetesFileFetcher(apiResourcePath))
	return b
}

// WithFilesystem configures filesystem support
func (b *CompositeFetcherBuilder) WithFilesystem(basePath string) *CompositeFetcherBuilder {
	b.fetcher.SetFilesystemFetcher(NewFilesystemFetcher(basePath))
	return b
}

// WithSystem configures system support
func (b *CompositeFetcherBuilder) WithSystem(allowArbitraryCommands bool) *CompositeFetcherBuilder {
	b.fetcher.SetSystemFetcher(NewSystemFetcher(30*time.Second, allowArbitraryCommands))
	return b
}

// WithCustomFetcher adds a custom fetcher
func (b *CompositeFetcherBuilder) WithCustomFetcher(inputType celscanner.InputType, fetcher celscanner.InputFetcher) *CompositeFetcherBuilder {
	b.fetcher.RegisterCustomFetcher(inputType, fetcher)
	return b
}

// Build returns the configured composite fetcher
func (b *CompositeFetcherBuilder) Build() *CompositeFetcher {
	return b.fetcher
}

// Example usage:
//
// // Create a comprehensive fetcher
// fetcher := NewCompositeFetcherBuilder().
//     WithKubernetes(client, clientset).
//     WithFilesystem("/etc").
//     WithSystem(false).
//     Build()
//
// // Create a file-only fetcher
// fetcher := NewCompositeFetcherBuilder().
//     WithKubernetesFiles("/path/to/api/resources").
//     WithFilesystem("/etc").
//     Build()
//
// // Use with mixed inputs
// inputs := []celscanner.Input{
//     celscanner.NewKubernetesInput("pods", "", "v1", "pods", "", ""),
//     celscanner.NewFileInput("config", "/etc/app/config.yaml", "yaml", false, false),
//     celscanner.NewSystemInput("nginx", "nginx", "", []string{}),
// }
//
// data, err := fetcher.FetchInputs(inputs, nil)
