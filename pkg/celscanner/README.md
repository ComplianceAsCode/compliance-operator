# CEL Scanner Module

A reusable Go module for performing CEL (Common Expression Language) based compliance scanning on Kubernetes resources.

## Overview

This module provides a clean, reusable API for evaluating CEL expressions against Kubernetes resources for compliance checking. It's designed to be framework-agnostic and can be integrated into various compliance scanning tools.

## Features

- **Clean Interface Design**: Uses Go interfaces for maximum flexibility and testability
- **Resource Fetching**: Supports both live API server fetching and pre-fetched file-based resources
- **CEL Expression Evaluation**: Full support for CEL expressions with custom functions (parseJSON, parseYAML)
- **Extensible Logging**: Pluggable logging interface
- **Compliance Operator Integration**: Includes adapters for seamless integration with existing compliance-operator types

## Architecture

The module is structured around several key interfaces:

- `Rule`: Defines a compliance rule with CEL expression
- `RuleInput`: Defines input resources needed for rule evaluation
- `KubeResource`: Defines Kubernetes resources to fetch
- `Variable`: Defines variables for rule evaluation
- `ResourceFetcher`: Interface for fetching Kubernetes resources
- `Logger`: Interface for logging operations

## Usage

### Basic Usage

```go
package main

import (
    "context"
    "fmt"
    
    "github.com/ComplianceAsCode/compliance-operator/pkg/celscanner"
)

func main() {
    // Create a scanner with default logger
    scanner := celscanner.NewScanner(nil, celscanner.DefaultLogger{})
    
    // Define your rules (implement the Rule interface)
    rules := []celscanner.Rule{
        // Your rule implementations
    }
    
    // Configure the scan
    config := celscanner.ScanConfig{
        Rules:           rules,
        Variables:       []celscanner.Variable{},
        ApiResourcePath: "/path/to/api/resources", // or empty for live API
    }
    
    // Execute the scan
    ctx := context.Background()
    results, err := scanner.Scan(ctx, config)
    if err != nil {
        fmt.Printf("Error scanning: %v\n", err)
        return
    }
    
    // Process results
    for _, result := range results {
        fmt.Printf("Rule: %s, Status: %s\n", result.Name, result.Status)
    }
    
    // Save results
    if err := celscanner.SaveResults("results.json", results); err != nil {
        fmt.Printf("Error saving results: %v\n", err)
    }
}
```

### Using with Kubernetes API

```go
package main

import (
    "context"
    
    "github.com/ComplianceAsCode/compliance-operator/pkg/celscanner"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/rest"
    runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func main() {
    // Get Kubernetes config
    config, err := rest.InClusterConfig()
    if err != nil {
        // Handle error
        return
    }
    
    // Create Kubernetes clients
    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        // Handle error
        return
    }
    
    client, err := runtimeclient.New(config, runtimeclient.Options{})
    if err != nil {
        // Handle error
        return
    }
    
    // Create resource fetcher for live API access
    resourceFetcher := celscanner.NewComplianceOperatorResourceFetcher(client, clientset)
    
    // Create scanner with resource fetcher
    scanner := celscanner.NewScanner(resourceFetcher, celscanner.DefaultLogger{})
    
    // Configure and run scan
    scanConfig := celscanner.ScanConfig{
        Rules:     rules, // Your rules
        Variables: variables, // Your variables
    }
    
    ctx := context.Background()
    results, err := scanner.Scan(ctx, scanConfig)
    // Process results...
}
```

### Using with Compliance Operator Types

```go
package main

import (
    "context"
    
    "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
    "github.com/ComplianceAsCode/compliance-operator/pkg/celscanner"
)

func main() {
    // Your existing compliance-operator types
    customRules := []*v1alpha1.CustomRule{
        // Your custom rules
    }
    
    variables := []*v1alpha1.Variable{
        // Your variables
    }
    
    // Adapt them to the scanner interfaces
    adaptedRules := celscanner.AdaptCustomRules(customRules)
    adaptedVariables := celscanner.AdaptVariables(variables)
    
    // Create scanner and run scan
    scanner := celscanner.NewScanner(resourceFetcher, celscanner.DefaultLogger{})
    
    scanConfig := celscanner.ScanConfig{
        Rules:     adaptedRules,
        Variables: adaptedVariables,
    }
    
    ctx := context.Background()
    results, err := scanner.Scan(ctx, scanConfig)
    
    // Convert results back to compliance-operator types if needed
    complianceCheckResults := celscanner.ConvertToComplianceCheckResults(results)
    
    // Process results...
}
```

## Implementing Custom Types

### Custom Rule Implementation

```go
type MyRule struct {
    name       string
    expression string
    inputs     []celscanner.RuleInput
    // ... other fields
}

func (r *MyRule) GetName() string        { return r.name }
func (r *MyRule) GetExpression() string  { return r.expression }
func (r *MyRule) GetInputs() []celscanner.RuleInput { return r.inputs }
// ... implement other interface methods
```

### Custom Resource Fetcher

```go
type MyResourceFetcher struct {
    // Your implementation
}

func (f *MyResourceFetcher) FetchResources(ctx context.Context, rule celscanner.Rule, variables []celscanner.Variable) (map[string]interface{}, []string, error) {
    // Your resource fetching logic
    return resourceMap, warnings, nil
}
```

### Custom Logger

```go
type MyLogger struct {
    // Your logger implementation
}

func (l *MyLogger) Debug(msg string, args ...interface{}) {
    // Your debug logging
}

func (l *MyLogger) Info(msg string, args ...interface{}) {
    // Your info logging
}

// ... implement other methods
```

## CEL Expression Support

The module supports standard CEL expressions with additional custom functions:

- `parseJSON(string)`: Parse JSON string to object
- `parseYAML(string)`: Parse YAML string to object

### Example CEL Expressions

```cel
// Check if any pods exist
pods.items.size() > 0

// Check pod security context
pods.items.all(pod, pod.spec.securityContext.runAsNonRoot == true)

// Check resource limits
pods.items.all(pod, 
  pod.spec.containers.all(container, 
    has(container.resources.limits) && 
    has(container.resources.limits.memory)
  )
)

// Parse JSON from annotation
parseJSON(configmap.data.config).enabled == true
```

## Testing

The module includes mock implementations for testing:

```go
func TestMyScanner(t *testing.T) {
    // Create mock rule
    mockRule := &celscanner.MockRule{
        name:       "test-rule",
        expression: "pods.items.size() > 0",
        inputs: []celscanner.RuleInput{
            &celscanner.MockRuleInput{
                name: "pods",
                kubeResource: &celscanner.MockKubeResource{
                    name:     "pods",
                    resource: "pods",
                    version:  "v1",
                },
            },
        },
    }
    
    // Create scanner with mock data
    scanner := celscanner.NewScanner(nil, celscanner.DefaultLogger{})
    
    // Test scan
    config := celscanner.ScanConfig{
        Rules:           []celscanner.Rule{mockRule},
        ApiResourcePath: "/test/resources",
    }
    
    results, err := scanner.Scan(context.Background(), config)
    // Assert results...
}
```

## Integration with Existing Systems

The module is designed to integrate easily with existing compliance scanning systems:

1. **Compliance Operator**: Direct integration through provided adapters
2. **Custom Systems**: Implement the interfaces for your specific types
3. **Testing**: Use mock implementations for unit testing
4. **CLI Tools**: Build command-line tools around the scanner
5. **Web Services**: Embed in web applications for compliance-as-a-service

## Dependencies

- `github.com/google/cel-go`: CEL expression evaluation
- `k8s.io/client-go`: Kubernetes client libraries
- `sigs.k8s.io/controller-runtime`: Controller runtime client
- `k8s.io/apimachinery`: Kubernetes API machinery

## Contributing

To contribute to this module:

1. Implement the required interfaces for your use case
2. Add tests for your implementations
3. Update documentation as needed
4. Submit a pull request

## License

This module is licensed under the Apache License, Version 2.0. 