# CEL Scanner Architecture Documentation

## Overview

The CEL Scanner is a flexible, extensible compliance checking framework that uses Google's Common Expression Language (CEL) to evaluate rules against various input sources including Kubernetes resources, filesystem data, and system information. This package provides a clean, type-safe interface for building compliance scanners with support for multiple input types and custom rule definitions.

## 🏗️ Architecture Principles

### Core Design Goals
- **Flexibility**: Support multiple input types (Kubernetes, Filesystem, System, HTTP, Database)
- **Extensibility**: Easy to add new input types and fetchers
- **Type Safety**: Strong typing with clear interfaces
- **Performance**: Efficient resource fetching and caching
- **Testability**: Comprehensive test coverage with mocking support

### Key Components
1. **Core Interfaces** - Define contracts for rules, inputs, and fetchers
2. **Input Fetchers** - Retrieve data from different sources
3. **Scanner Engine** - Orchestrates rule evaluation
4. **Adapters** - Bridge legacy compliance-operator types
5. **Examples** - Demonstrate usage patterns

## 📁 File Structure

```
pkg/celscanner/
├── Core Components
│   ├── interfaces.go          # Core interfaces and types
│   ├── scanner.go             # Main scanner implementation
│   └── adapters.go            # Legacy compliance-operator adapters
│
├── Input Fetchers
│   └── inputs/
│       ├── filesystem.go      # File system input fetcher
│       ├── filesystem_test.go # Comprehensive filesystem tests
│       ├── kubernetes.go      # Kubernetes resource fetcher
│       ├── kubernetes_test.go # Kubernetes fetcher tests
│       ├── system.go          # System service/process fetcher
│       └── composite.go       # Multi-source input fetcher
│
├── Examples & Usage
│   └── examples/
│       ├── comprehensive_usage.go        # Complete usage examples
│       ├── dynamic_config_example.go     # Dynamic configuration
│       └── resource-mappings-example.json # Resource mapping config
│
├── Test Data
│   └── testdata/
│       ├── pods.json          # Sample Kubernetes pods
│       ├── services.json      # Sample Kubernetes services
│       ├── configmaps.json    # Sample ConfigMaps
│       └── namespaces/
│           └── default/
│               └── pods.json  # Namespace-specific test data
│
├── Tests
│   ├── scanner_test.go        # Scanner unit tests
│   ├── integration_test.go    # Integration tests
│   └── benchmark_test.go      # Performance benchmarks
│
└── Documentation
    ├── README.md              # Basic usage and examples
    ├── TEST_RUNNER.md         # Test execution guide
    ├── USAGE_GUIDE.md         # Practical usage guide
    └── ARCHITECTURE.md        # This file
```

## 🔧 Core Components

### 1. Interfaces (`interfaces.go`)

#### Primary Interfaces

```go
// CelRule - Simplified rule interface
type CelRule interface {
    Identifier() string    // Unique rule ID
    Expression() string    // CEL expression
    Inputs() []Input      // Required inputs
}

// Input - Generic input specification
type Input interface {
    Name() string         // Input name for CEL context
    Type() InputType      // Input type (kubernetes, file, system)
    Spec() InputSpec      // Type-specific specification
}

// InputFetcher - Data retrieval interface
type InputFetcher interface {
    FetchInputs([]Input, []CelVariable) (map[string]interface{}, error)
    SupportsInputType(InputType) bool
}
```

#### Input Type Specifications

```go
// KubernetesInputSpec - Kubernetes resource specification
type KubernetesInputSpec interface {
    ApiGroup() string     // API group (e.g., "apps", "")
    Version() string      // API version (e.g., "v1")
    ResourceType() string // Resource type (e.g., "pods")
    Namespace() string    // Target namespace
    Name() string         // Specific resource name
}

// FileInputSpec - Filesystem input specification
type FileInputSpec interface {
    Path() string             // File or directory path
    Format() string           // File format (json, yaml, text)
    Recursive() bool          // Recursive directory traversal
    CheckPermissions() bool   // Include file permissions
}

// SystemInputSpec - System service/process specification
type SystemInputSpec interface {
    ServiceName() string  // System service name
    Command() string      // Command to execute
    Args() []string       // Command arguments
}
```

### 2. Scanner Engine (`scanner.go`)

The main scanner orchestrates rule evaluation:

```go
type Scanner struct {
    fetcher InputFetcher  // Data source
    logger  ScanLogger    // Logging interface
}

// Main scanning method
func (s *Scanner) Scan(ctx context.Context, config ScanConfig) ([]CheckResult, error)
```

**Key Features:**
- **Concurrent Evaluation**: Rules are evaluated in parallel
- **Error Isolation**: Failed rules don't stop others
- **Resource Caching**: Efficient data fetching
- **Timeout Handling**: Configurable timeouts per rule
- **Comprehensive Logging**: Detailed operation logging

### 3. Input Fetchers (`inputs/`)

#### Filesystem Fetcher (`filesystem.go`)
- **File Reading**: Support for JSON, YAML, and text files
- **Directory Traversal**: Recursive and non-recursive options
- **Permission Checking**: File mode, owner, group, size information
- **Format Inference**: Automatic format detection from extensions
- **Error Handling**: Graceful handling of missing files

**Enhanced Permission Support:**
```go
// When CheckPermissions() is true, returns:
{
    "content": <parsed_content>,
    "mode":    "-rw-r--r--",     // File mode string
    "perm":    "0644",           // Octal permissions
    "owner":   "root",           // Owner username
    "group":   "root",           // Group name
    "size":    1024              // File size in bytes
}
```

#### Kubernetes Fetcher (`kubernetes.go`)
- **Resource Discovery**: Dynamic API discovery
- **Namespace Support**: Cluster-scoped and namespaced resources
- **Custom Resources**: Support for CRDs
- **Resource Mapping**: Configurable GVK mappings
- **Caching**: Efficient resource caching

#### System Fetcher (`system.go`)
- **Service Status**: systemd service monitoring
- **Command Execution**: Execute system commands
- **Process Information**: Process status and details
- **Security**: Restricted execution environment

#### Composite Fetcher (`composite.go`)
- **Multi-Source**: Combines multiple fetchers
- **Builder Pattern**: Fluent configuration API
- **Fallback Logic**: Graceful degradation
- **Resource Optimization**: Efficient resource usage

### 4. Legacy Adapters (`adapters.go`)

Provides compatibility with existing compliance-operator types:

```go
// Adapt legacy types to new interfaces
func AdaptCustomRules([]*v1alpha1.CustomRule) []Rule
func AdaptVariables([]*v1alpha1.Variable) []Variable
func ConvertToComplianceCheckResults([]CheckResult) []*v1alpha1.ComplianceCheckResult
```

## 🚀 Usage Patterns

### Basic Usage

```go
// 1. Create input fetcher
fetcher := inputs.NewCompositeFetcherBuilder().
    WithKubernetes(client, clientset).
    WithFilesystem("/etc").
    WithSystem(false).
    Build()

// 2. Create scanner
scanner := celscanner.NewScanner(fetcher, logger)

// 3. Define rules
rule := celscanner.NewRule("pod-security",
    "pods.items.all(pod, has(pod.spec.securityContext))",
    []celscanner.Input{
        celscanner.NewKubernetesInput("pods", "", "v1", "pods", "default", ""),
    })

// 4. Execute scan
results, err := scanner.Scan(ctx, celscanner.ScanConfig{
    Rules: []celscanner.Rule{rule},
})
```

### File Permission Checking

```go
// Check file with permissions
input := celscanner.NewFileInput("config", "/etc/app/config.yaml", "yaml", false, true)
rule := celscanner.NewRule("secure-config",
    "config.perm == '0600' && config.owner == 'root'",
    []celscanner.Input{input})
```

### Multi-Source Rules

```go
// Combine Kubernetes, filesystem, and system inputs
kubeInput := celscanner.NewKubernetesInput("pods", "", "v1", "pods", "production", "")
fileInput := celscanner.NewFileInput("policy", "/etc/security/policy.yaml", "yaml", false, false)
systemInput := celscanner.NewSystemInput("audit", "", "auditctl", []string{"-s"})

rule := celscanner.NewRule("comprehensive-security",
    "pods.items.all(pod, pod.spec.securityContext.runAsNonRoot) && " +
    "policy.security.enforce && " +
    "audit.enabled",
    []celscanner.Input{kubeInput, fileInput, systemInput})
```

## 🧪 Testing Strategy

### Test Coverage
- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end workflow testing
- **Benchmark Tests**: Performance characterization
- **Example Tests**: Usage pattern validation

### Test Categories

1. **Filesystem Tests** (`filesystem_test.go`)
   - File content parsing (JSON, YAML, text)
   - Directory traversal (recursive/non-recursive)
   - Permission checking (various modes)
   - Error handling (missing files, invalid content)
   - Format inference and filtering
   - Helper function validation

2. **Kubernetes Tests** (`kubernetes_test.go`)
   - Resource discovery and mapping
   - Namespace handling
   - Custom resource support
   - Error scenarios

3. **Scanner Tests** (`scanner_test.go`)
   - Rule evaluation logic
   - Concurrent processing
   - Error isolation
   - Timeout handling

4. **Integration Tests** (`integration_test.go`)
   - Multi-fetcher scenarios
   - Legacy adapter compatibility
   - End-to-end workflows

5. **Benchmark Tests** (`benchmark_test.go`)
   - Performance characterization
   - Memory usage analysis
   - Concurrency scaling

### Performance Metrics

Recent benchmark results:
```
BenchmarkFilesystemFetcher_FetchTextFile-32        405,582 ops/sec  (2.7μs/op)
BenchmarkFilesystemFetcher_FetchWithPermissions-32   7,682 ops/sec  (558μs/op)
BenchmarkFilesystemFetcher_FetchDirectory-32        38,612 ops/sec  (29.6μs/op)
```

## 🔌 Extension Points

### Adding New Input Types

1. **Define Input Spec Interface**
```go
type HTTPInputSpec interface {
    InputSpec
    URL() string
    Method() string
    Headers() map[string]string
}
```

2. **Create Input Fetcher**
```go
type HTTPFetcher struct {
    client *http.Client
}

func (f *HTTPFetcher) FetchInputs(inputs []Input, variables []CelVariable) (map[string]interface{}, error)
func (f *HTTPFetcher) SupportsInputType(inputType InputType) bool
```

3. **Register with Composite Fetcher**
```go
fetcher := inputs.NewCompositeFetcherBuilder().
    WithHTTP(httpClient).
    Build()
```

### Custom Resource Mappings

Configure custom Kubernetes resource mappings:
```json
{
  "resourceMappings": {
    "securitycontextconstraints": {
      "group": "security.openshift.io",
      "version": "v1",
      "kind": "SecurityContextConstraints",
      "namespaced": false
    }
  }
}
```

## 🔒 Security Considerations

### File System Access
- **Path Validation**: Prevent directory traversal attacks
- **Permission Checks**: Validate file access permissions
- **Sandboxing**: Restrict file system access scope

### System Command Execution
- **Command Whitelisting**: Only allow approved commands
- **Argument Sanitization**: Prevent command injection
- **Execution Limits**: Timeout and resource constraints

### Kubernetes Access
- **RBAC Integration**: Respect Kubernetes RBAC policies
- **Namespace Isolation**: Enforce namespace boundaries
- **Resource Limits**: Prevent resource exhaustion

## 📊 Monitoring and Observability

### Logging Levels
- **Debug**: Detailed operation tracing
- **Info**: General operation information
- **Warn**: Non-fatal issues and warnings
- **Error**: Fatal errors and failures

### Metrics
- Rule evaluation duration
- Input fetching performance
- Error rates by input type
- Resource cache hit/miss ratios

### Health Checks
- Input fetcher availability
- Resource connectivity
- Permission validation

## 🚦 Best Practices

### Rule Design
1. **Specific Expressions**: Write clear, specific CEL expressions
2. **Input Minimization**: Only request needed inputs
3. **Error Handling**: Handle missing or invalid data gracefully
4. **Performance**: Consider expression complexity

### Fetcher Configuration
1. **Resource Limits**: Set appropriate timeouts and limits
2. **Caching Strategy**: Configure efficient caching
3. **Error Recovery**: Implement retry logic
4. **Security**: Follow principle of least privilege

### Testing
1. **Comprehensive Coverage**: Test all code paths
2. **Edge Cases**: Test error conditions and edge cases
3. **Performance**: Include benchmark tests
4. **Integration**: Test real-world scenarios

## 📚 Additional Resources

- **README.md**: Quick start guide and basic examples
- **USAGE_GUIDE.md**: Practical usage guide and examples
- **TEST_RUNNER.md**: Test execution and CI/CD integration
- **examples/**: Comprehensive usage examples
- **testdata/**: Sample data for testing

## 🔄 Migration Guide

### From Legacy Compliance Operator

1. **Use Adapters**: Leverage existing adapter functions
2. **Gradual Migration**: Migrate rules incrementally
3. **Compatibility Layer**: Maintain backward compatibility
4. **Testing**: Validate migrated functionality

### Upgrading Existing Rules

1. **Interface Updates**: Update to new interface contracts
2. **Input Specifications**: Migrate to typed input specs
3. **Error Handling**: Implement proper error handling
4. **Performance**: Optimize for new architecture

This architecture provides a solid foundation for building flexible, maintainable compliance scanning solutions while maintaining compatibility with existing systems. 