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
	"fmt"

	"github.com/ComplianceAsCode/compliance-sdk/pkg/scanner"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// CelVariable implements CelVariable interface for conversion
type CelVariable struct {
	name      string
	namespace string
	value     string
	gvk       schema.GroupVersionKind
}

func (v *CelVariable) Name() string                              { return v.name }
func (v *CelVariable) Namespace() string                         { return v.namespace }
func (v *CelVariable) Value() string                             { return v.value }
func (v *CelVariable) GroupVersionKind() schema.GroupVersionKind { return v.gvk }

// CompositeFetcher implements InputFetcher by delegating to specialized fetchers
type CompositeFetcher struct {
	kubernetesFetcher *KubernetesFetcher
	filesystemFetcher *FilesystemFetcher

	// Registry of custom fetchers for extensibility
	customFetchers map[scanner.InputType]scanner.InputFetcher
}

// NewCompositeFetcher creates a new composite input fetcher with default implementations
func NewCompositeFetcher() *CompositeFetcher {
	return &CompositeFetcher{
		customFetchers: make(map[scanner.InputType]scanner.InputFetcher),
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

	return fetcher
}

// FetchResources implements the ResourceFetcher interface using the new unified API
func (c *CompositeFetcher) FetchResources(ctx context.Context, rule scanner.Rule, variables []scanner.CelVariable) (map[string]interface{}, []string, error) {
	// Use the new unified API directly
	inputs := rule.Inputs()

	data, err := c.FetchInputs(inputs, variables)
	if err != nil {
		return nil, nil, err
	}

	return data, nil, nil
}

// FetchInputs retrieves inputs by delegating to appropriate specialized fetchers
func (c *CompositeFetcher) FetchInputs(inputs []scanner.Input, variables []scanner.CelVariable) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// Group inputs by type
	inputsByType := make(map[scanner.InputType][]scanner.Input)
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
func (c *CompositeFetcher) SupportsInputType(inputType scanner.InputType) bool {
	return c.getFetcherForType(inputType) != nil
}

// getFetcherForType returns the appropriate fetcher for the input type
func (c *CompositeFetcher) getFetcherForType(inputType scanner.InputType) scanner.InputFetcher {
	// Check custom fetchers first
	if fetcher, exists := c.customFetchers[inputType]; exists {
		return fetcher
	}

	// Check built-in fetchers
	switch inputType {
	case scanner.InputTypeKubernetes:
		return c.kubernetesFetcher
	case scanner.InputTypeFile:
		return c.filesystemFetcher

	default:
		return nil
	}
}

// RegisterCustomFetcher registers a custom fetcher for a specific input type
func (c *CompositeFetcher) RegisterCustomFetcher(inputType scanner.InputType, fetcher scanner.InputFetcher) {
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

// GetSupportedInputTypes returns all supported input types
func (c *CompositeFetcher) GetSupportedInputTypes() []scanner.InputType {
	var types []scanner.InputType

	// Add built-in types
	if c.kubernetesFetcher != nil {
		types = append(types, scanner.InputTypeKubernetes)
	}
	if c.filesystemFetcher != nil {
		types = append(types, scanner.InputTypeFile)
	}

	// Add custom types
	for inputType := range c.customFetchers {
		types = append(types, inputType)
	}

	return types
}

// ValidateInputs validates all inputs are supported
func (c *CompositeFetcher) ValidateInputs(inputs []scanner.Input) error {
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

// WithCustomFetcher adds a custom fetcher
func (b *CompositeFetcherBuilder) WithCustomFetcher(inputType scanner.InputType, fetcher scanner.InputFetcher) *CompositeFetcherBuilder {
	b.fetcher.RegisterCustomFetcher(inputType, fetcher)
	return b
}

// Build returns the configured composite fetcher
func (b *CompositeFetcherBuilder) Build() *CompositeFetcher {
	return b.fetcher
}
