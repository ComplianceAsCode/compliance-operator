# CEL Scanner Usage Guide

## Quick Start

The CEL Scanner provides a flexible framework for compliance checking using Google's Common Expression Language (CEL). This guide shows you how to use it effectively.

## 🚀 Basic Setup

### 1. Import the Package

```go
import (
    "github.com/ComplianceAsCode/compliance-operator/pkg/celscanner"
    "github.com/ComplianceAsCode/compliance-operator/pkg/celscanner/inputs"
)
```

### 2. Create an Input Fetcher

```go
// Create a composite fetcher that supports multiple input types
fetcher := inputs.NewCompositeFetcherBuilder().
    WithKubernetes(client, clientset).  // Kubernetes resources
    WithFilesystem("/etc").             // File system access
    WithSystem(false).                  // System commands (restricted)
    Build()
```

### 3. Create a Scanner

```go
// Simple logger implementation
logger := &SimpleLogger{}

// Create the scanner
scanner := celscanner.NewScanner(fetcher, logger)
```

## 📝 Writing Rules

### Simple Kubernetes Rule

```go
// Check if pods have resource limits
input := celscanner.NewKubernetesInput("pods", "", "v1", "pods", "production", "")
rule := celscanner.NewRule("pod-resources",
    "pods.items.all(pod, pod.spec.containers.all(c, has(c.resources.limits)))",
    []celscanner.Input{input})
```

### File Configuration Rule

```go
// Check application configuration
input := celscanner.NewFileInput("config", "/etc/app/config.yaml", "yaml", false, false)
rule := celscanner.NewRule("config-security",
    "config.security.enabled && config.security.tls.minVersion >= 1.2",
    []celscanner.Input{input})
```

### File Permission Rule

```go
// Check file permissions and ownership
input := celscanner.NewFileInput("secrets", "/etc/app/secrets.yaml", "yaml", false, true)
rule := celscanner.NewRule("secrets-secure",
    "secrets.perm == '0600' && secrets.owner == 'root' && secrets.group == 'root'",
    []celscanner.Input{input})
```

### System Service Rule

```go
// Check if required services are running
nginxInput := celscanner.NewSystemInput("nginx", "nginx", "", []string{})
rule := celscanner.NewRule("nginx-running",
    "nginx.status == 'active'",
    []celscanner.Input{nginxInput})
```

### Multi-Source Rule

```go
// Combine multiple input types
kubeInput := celscanner.NewKubernetesInput("pods", "", "v1", "pods", "default", "")
fileInput := celscanner.NewFileInput("policy", "/etc/security/policy.yaml", "yaml", false, false)
systemInput := celscanner.NewSystemInput("audit", "", "auditctl", []string{"-s"})

rule := celscanner.NewRule("comprehensive-security",
    "pods.items.all(pod, pod.spec.securityContext.runAsNonRoot) && " +
    "policy.security.enforce && " +
    "audit.enabled",
    []celscanner.Input{kubeInput, fileInput, systemInput})
```

## 🏃 Running Scans

### Execute Rules

```go
// Create scan configuration
config := celscanner.ScanConfig{
    Rules: []celscanner.Rule{rule1, rule2, rule3},
}

// Execute scan
ctx := context.Background()
results, err := scanner.Scan(ctx, config)
if err != nil {
    log.Fatalf("Scan failed: %v", err)
}

// Process results
for _, result := range results {
    fmt.Printf("Rule: %s, Status: %s, Message: %s\n", 
        result.ID, result.Status, result.Message)
}
```

## 📁 File System Usage

### Reading Configuration Files

```go
// JSON configuration
jsonInput := celscanner.NewFileInput("config", "/etc/app/config.json", "json", false, false)

// YAML configuration  
yamlInput := celscanner.NewFileInput("config", "/etc/app/config.yaml", "yaml", false, false)

// Text file
textInput := celscanner.NewFileInput("version", "/etc/app/VERSION", "text", false, false)

// Auto-detect format from extension
autoInput := celscanner.NewFileInput("config", "/etc/app/config.json", "", false, false)
```

### Directory Scanning

```go
// Scan directory non-recursively
dirInput := celscanner.NewFileInput("configs", "/etc/app/configs", "yaml", false, false)

// Scan directory recursively
recursiveInput := celscanner.NewFileInput("all_configs", "/etc/app", "yaml", true, false)

// Scan with permission checking
permInput := celscanner.NewFileInput("secure_configs", "/etc/app/secrets", "yaml", false, true)
```

### CEL Expressions for Files

```go
// Check file content
"config.server.port == 8080"

// Check file permissions
"config.perm == '0644' && config.owner == 'app'"

// Check file size
"config.size > 0 && config.size < 1048576"  // Between 0 and 1MB

// Check directory contents
"configs.size() > 0"  // Directory has files

// Complex file validation
"has(config.content) && config.content.security.enabled && config.perm == '0600'"
```

## ☸️ Kubernetes Usage

### Resource Queries

```go
// All pods in a namespace
podsInput := celscanner.NewKubernetesInput("pods", "", "v1", "pods", "production", "")

// Specific pod
podInput := celscanner.NewKubernetesInput("app_pod", "", "v1", "pods", "production", "my-app")

// Deployments
deployInput := celscanner.NewKubernetesInput("deployments", "apps", "v1", "deployments", "production", "")

// Services
serviceInput := celscanner.NewKubernetesInput("services", "", "v1", "services", "production", "")

// ConfigMaps
configInput := celscanner.NewKubernetesInput("configs", "", "v1", "configmaps", "production", "")

// Custom Resources (example: SecurityContextConstraints)
sccInput := celscanner.NewKubernetesInput("sccs", "security.openshift.io", "v1", "securitycontextconstraints", "", "")
```

### CEL Expressions for Kubernetes

```go
// Check if pods exist
"pods.items.size() > 0"

// All pods have resource limits
"pods.items.all(pod, pod.spec.containers.all(c, has(c.resources.limits)))"

// No privileged pods
"pods.items.all(pod, !pod.spec.securityContext.privileged)"

// All pods run as non-root
"pods.items.all(pod, pod.spec.securityContext.runAsNonRoot == true)"

// Check deployment replicas
"deployments.items.all(dep, dep.spec.replicas >= 2)"

// Services don't use NodePort
"services.items.all(svc, svc.spec.type != 'NodePort')"

// ConfigMaps contain required keys
"configs.items.all(cm, has(cm.data.database_url))"
```

## 🖥️ System Usage

### Service Monitoring

```go
// Check systemd service status
serviceInput := celscanner.NewSystemInput("nginx", "nginx", "", []string{})

// Execute system command
uptimeInput := celscanner.NewSystemInput("uptime", "", "uptime", []string{})

// Check process with arguments
psInput := celscanner.NewSystemInput("processes", "", "ps", []string{"aux"})
```

### CEL Expressions for System

```go
// Service is active
"nginx.status == 'active'"

// Command executed successfully
"has(uptime.output) && uptime.exitCode == 0"

// System uptime check
"uptime.output.contains('up') && !uptime.output.contains('0 min')"

// Process count
"processes.output.split('\n').size() > 10"
```

## 🔧 Advanced Usage

### Custom Resource Mappings

```go
// Create fetcher with custom mappings
fetcher := inputs.NewCompositeFetcherBuilder().
    WithKubernetesFiles("./custom-mappings.json").
    WithFilesystem("/etc").
    Build()
```

Custom mappings file (`custom-mappings.json`):
```json
{
  "resourceMappings": {
    "securitycontextconstraints": {
      "group": "security.openshift.io",
      "version": "v1", 
      "kind": "SecurityContextConstraints",
      "namespaced": false
    },
    "clusterroles": {
      "group": "rbac.authorization.k8s.io",
      "version": "v1",
      "kind": "ClusterRole", 
      "namespaced": false
    }
  }
}
```

### Error Handling

```go
// Rules with error handling
rule := celscanner.NewRule("safe-check",
    "has(pods) ? pods.items.size() > 0 : false",  // Handle missing input
    []celscanner.Input{input})

// File existence check
rule := celscanner.NewRule("file-exists",
    "has(config.content) ? config.content.enabled : false",
    []celscanner.Input{fileInput})
```

### Performance Optimization

```go
// Use specific resource names when possible
specificInput := celscanner.NewKubernetesInput("app_pod", "", "v1", "pods", "production", "my-app")

// Limit directory recursion
limitedInput := celscanner.NewFileInput("configs", "/etc/app/configs", "yaml", false, false)

// Avoid expensive operations in CEL
// Good: "pods.items.size() > 0"
// Bad: "pods.items.map(pod, pod.spec.containers.size()).sum() > 10"
```

## 🧪 Testing Your Rules

### Unit Testing

```go
func TestMyRule(t *testing.T) {
    // Create mock fetcher
    mockFetcher := &MockFetcher{
        data: map[string]interface{}{
            "pods": mockPodsList,
        },
    }
    
    scanner := celscanner.NewScanner(mockFetcher, &TestLogger{})
    
    rule := celscanner.NewRule("test-rule", "pods.items.size() > 0", []celscanner.Input{
        celscanner.NewKubernetesInput("pods", "", "v1", "pods", "default", ""),
    })
    
    results, err := scanner.Scan(context.Background(), celscanner.ScanConfig{
        Rules: []celscanner.Rule{rule},
    })
    
    assert.NoError(t, err)
    assert.Len(t, results, 1)
    assert.Equal(t, celscanner.CheckResultPass, results[0].Status)
}
```

### Integration Testing

```go
func TestIntegration(t *testing.T) {
    // Use real fetcher with test data
    fetcher := inputs.NewCompositeFetcherBuilder().
        WithKubernetesFiles("./testdata").
        WithFilesystem("./testdata").
        Build()
    
    scanner := celscanner.NewScanner(fetcher, &TestLogger{})
    
    // Test with real-like data
    // ...
}
```

## 🔍 Debugging

### Enable Detailed Logging

```go
type DebugLogger struct{}

func (l *DebugLogger) Debug(msg string, args ...interface{}) {
    log.Printf("[DEBUG] "+msg, args...)
}

func (l *DebugLogger) Info(msg string, args ...interface{}) {
    log.Printf("[INFO] "+msg, args...)
}

func (l *DebugLogger) Error(msg string, args ...interface{}) {
    log.Printf("[ERROR] "+msg, args...)
}

scanner := celscanner.NewScanner(fetcher, &DebugLogger{})
```

### Inspect Input Data

```go
// Add debug rule to see input data
debugRule := celscanner.NewRule("debug",
    "true",  // Always passes
    []celscanner.Input{input})

results, _ := scanner.Scan(ctx, celscanner.ScanConfig{Rules: []celscanner.Rule{debugRule}})
fmt.Printf("Input data: %+v\n", results[0].Details)
```

## 🚨 Common Pitfalls

### 1. Missing Input Validation

```go
// Bad: Assumes input exists
"config.server.port > 0"

// Good: Check if input exists
"has(config) && has(config.server) && config.server.port > 0"
```

### 2. Incorrect File Paths

```go
// Bad: Hardcoded absolute paths
"/home/user/config.yaml"

// Good: Use configurable base paths
fetcher := inputs.NewFilesystemFetcher("/app/config")
input := celscanner.NewFileInput("config", "config.yaml", "yaml", false, false)
```

### 3. Overly Complex CEL Expressions

```go
// Bad: Complex nested operations
"pods.items.map(pod, pod.spec.containers.map(c, c.resources.limits.memory)).flatten().all(mem, mem != null)"

// Good: Simpler, more readable
"pods.items.all(pod, pod.spec.containers.all(c, has(c.resources.limits.memory)))"
```

### 4. Ignoring Permissions

```go
// For security-sensitive files, always check permissions
input := celscanner.NewFileInput("secrets", "/etc/secrets.yaml", "yaml", false, true)
rule := celscanner.NewRule("secrets-secure",
    "secrets.perm == '0600' && secrets.owner == 'root'",
    []celscanner.Input{input})
```

## 📚 Examples Repository

See the `examples/` directory for complete working examples:

- `comprehensive_usage.go` - Complete usage patterns
- `dynamic_config_example.go` - Dynamic configuration
- `resource-mappings-example.json` - Custom resource mappings

## 🔗 Additional Resources

- [CEL Language Guide](https://github.com/google/cel-spec/blob/master/doc/langdef.md)
- [Architecture Documentation](./ARCHITECTURE.md)
- [Test Runner Guide](./TEST_RUNNER.md) 