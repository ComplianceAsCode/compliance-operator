# CEL Scanner Test Suite

This directory contains comprehensive tests for the CEL scanner module using real cluster mock resources.

## Test Structure

### Test Files

1. **`scanner_test.go`** - Core functionality tests with real Kubernetes resource data
2. **`integration_test.go`** - Integration tests with compliance-operator types and adapters
3. **`benchmark_test.go`** - Performance and benchmark tests with various cluster sizes

### Test Data

- **`testdata/`** - Contains realistic Kubernetes resource JSON files
  - `pods.json` - Mock Pod resources with various security configurations
  - `configmaps.json` - Mock ConfigMap resources with YAML/JSON data
  - `services.json` - Mock Service resources
  - `namespaces/default/pods.json` - Namespace-scoped resources

## Running Tests

### Prerequisites

```bash
cd pkg/celscanner
```

### Unit Tests

Run all unit tests:
```bash
go test -v ./...
```

Run specific test categories:
```bash
# Core scanner functionality
go test -v -run TestScanner_Scan_WithMockResources

# Error handling
go test -v -run TestScanner_ErrorHandling

# Variable handling
go test -v -run TestScanner_WithVariables
```

### Integration Tests

Run integration tests with compliance-operator types:
```bash
# Adapter tests
go test -v -run TestAdapters_ComplianceOperatorTypes

# Mock resource fetcher integration
go test -v -run TestIntegration_ScannerWithMockResourceFetcher

# Real-world scenarios
go test -v -run TestIntegration_RealWorldScenarios
```

### Benchmark Tests

Run performance benchmarks:
```bash
# All benchmarks
go test -bench=. -benchmem

# Specific benchmark categories
go test -bench=BenchmarkScanner_SingleRule -benchmem
go test -bench=BenchmarkScanner_MultipleRules -benchmem
go test -bench=BenchmarkCELExpressionComplexity -benchmem
go test -bench=BenchmarkResourceFetching -benchmem
```

### Full Test Suite

Run everything with coverage:
```bash
go test -v -race -cover -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

## Test Scenarios Covered

### 1. Basic Functionality Tests (`scanner_test.go`)

- **Pod Existence Check**: Verifies scanner can detect if pods exist
- **Security Context Validation**: Tests pod security compliance rules
- **Resource Limits Check**: Validates container resource configurations
- **ConfigMap Data Validation**: Tests ConfigMap data existence and structure
- **JSON Parsing**: Tests `parseJSON()` CEL function with ConfigMap data
- **Service Type Validation**: Tests service type checks
- **Multi-Resource Rules**: Tests rules that span multiple resource types

### 2. Integration Tests (`integration_test.go`)

- **Adapter Functionality**: Tests compliance-operator type adapters
- **Mock Resource Fetcher**: Tests scanner with mock resource fetcher
- **Type Conversion**: Tests converting between scanner and compliance-operator types
- **Real-World Scenarios**: 
  - Pod security compliance
  - Network policy enforcement
  - Resource quota validation

### 3. Performance Tests (`benchmark_test.go`)

- **Cluster Size Scaling**: Tests with 10, 100, 1000 pods
- **Rule Count Scaling**: Tests with 1, 5+ rules
- **Expression Complexity**: Tests simple to complex CEL expressions
- **Resource Fetching**: Benchmarks resource fetching performance

## Test Data Characteristics

### Realistic Mock Data

The test data includes realistic Kubernetes resources that represent common cluster scenarios:

#### Pods (`testdata/pods.json`)
- Mix of secure and insecure configurations
- Various resource limit configurations
- Different security contexts (root/non-root)
- Multiple namespaces

#### ConfigMaps (`testdata/configmaps.json`)
- YAML and JSON data content
- Configuration files
- Feature flags in JSON format

#### Services (`testdata/services.json`)
- ClusterIP and LoadBalancer types
- Various port configurations
- Service selectors matching pod labels

## Example Test Runs

### Running Basic Tests
```bash
$ go test -v -run TestScanner_Scan_WithMockResources
=== RUN   TestScanner_Scan_WithMockResources
=== RUN   TestScanner_Scan_WithMockResources/pods_exist_check
[INFO] Processing rule: pods-exist
[INFO] Using pre-fetched resources from: /tmp/test-data...
    scanner_test.go:XXX: Test 'pods exist check' completed: Should pass when pods exist
=== RUN   TestScanner_Scan_WithMockResources/pod_security_context_check
    scanner_test.go:XXX: Test 'pod security context check' completed: Should fail when not all pods run as non-root
=== RUN   TestScanner_Scan_WithMockResources/configmap_json_parsing
    scanner_test.go:XXX: Test 'configmap json parsing' completed: Should pass when JSON parsing works and auth feature is enabled
--- PASS: TestScanner_Scan_WithMockResources (0.XX s)
```

### Running Benchmarks
```bash
$ go test -bench=BenchmarkScanner_SingleRule -benchmem
BenchmarkScanner_SingleRule_SmallCluster-8    	    1000	   1234567 ns/op	   12345 B/op	     123 allocs/op
BenchmarkScanner_SingleRule_MediumCluster-8   	     100	  12345678 ns/op	  123456 B/op	    1234 allocs/op
BenchmarkScanner_SingleRule_LargeCluster-8    	      10	 123456789 ns/op	 1234567 B/op	   12345 allocs/op
```

## Writing New Tests

### Adding Test Cases

1. **Create Mock Data**: Add realistic Kubernetes resources to `testdata/`
2. **Write Test Functions**: Follow the existing pattern in test files
3. **Use Test Helpers**: Leverage existing helper functions for setup

### Test Pattern Example

```go
func TestMyNewScenario(t *testing.T) {
    // Setup
    scanner := NewScanner(nil, &TestLogger{t: t})
    testDataDir := setupTestData(t)
    
    // Create rule
    rule := &TestRule{
        name:       "my-rule",
        expression: "pods.items.all(pod, pod.status.phase == 'Running')",
        inputs: []RuleInput{
            &TestRuleInput{
                name: "pods",
                kubeResource: &TestKubeResource{
                    name:     "pods",
                    resource: "pods",
                },
            },
        },
    }
    
    // Execute
    config := ScanConfig{Rules: []Rule{rule}, ApiResourcePath: testDataDir}
    results, err := scanner.Scan(context.Background(), config)
    
    // Verify
    if err != nil {
        t.Fatalf("Unexpected error: %v", err)
    }
    if len(results) != 1 {
        t.Fatalf("Expected 1 result, got %d", len(results))
    }
    if results[0].Status != CheckResultPass {
        t.Errorf("Expected PASS, got %s", results[0].Status)
    }
}
```

## Continuous Integration

For CI/CD pipelines, use:

```bash
# Fast test run
go test -short ./...

# Full test suite with race detection
go test -race -timeout 5m ./...

# Benchmarks for performance regression
go test -bench=. -benchtime=1s -timeout 10m ./...
```

## Test Coverage Goals

- **Functionality**: >90% code coverage
- **Error Paths**: All error conditions tested
- **CEL Expressions**: Various complexity levels covered
- **Resource Types**: Multiple Kubernetes resource types
- **Performance**: Benchmarks for all major operations

## Debugging Tests

### Verbose Output
```bash
go test -v -run TestSpecificTest
```

### Test with Debug Logging
```bash
# Tests will show debug output via TestLogger
go test -v -run TestScanner_Scan_WithMockResources
```

### Analyzing Benchmark Results
```bash
go test -bench=. -cpuprofile=cpu.prof -memprofile=mem.prof
go tool pprof cpu.prof
go tool pprof mem.prof
``` 