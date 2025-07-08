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
	"context"
	"fmt"
	"log"

	"github.com/ComplianceAsCode/compliance-operator/pkg/celscanner"
	"github.com/ComplianceAsCode/compliance-operator/pkg/celscanner/inputs"
	"k8s.io/client-go/kubernetes"
	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// CelRuleAdapter adapts CelRule to Rule interface for backwards compatibility
type CelRuleAdapter struct {
	celRule celscanner.CelRule
}

func (a *CelRuleAdapter) GetName() string         { return a.celRule.Identifier() }
func (a *CelRuleAdapter) GetNamespace() string    { return "default" }
func (a *CelRuleAdapter) GetID() string           { return a.celRule.Identifier() }
func (a *CelRuleAdapter) GetDescription() string  { return "CEL rule: " + a.celRule.Identifier() }
func (a *CelRuleAdapter) GetRationale() string    { return "Generated from CelRule" }
func (a *CelRuleAdapter) GetSeverity() string     { return "medium" }
func (a *CelRuleAdapter) GetInstructions() string { return "Fix any issues found" }
func (a *CelRuleAdapter) GetTitle() string        { return a.celRule.Identifier() }
func (a *CelRuleAdapter) GetErrorMessage() string { return "Rule failed" }
func (a *CelRuleAdapter) GetExpression() string   { return a.celRule.Expression() }
func (a *CelRuleAdapter) GetInputs() []celscanner.RuleInput {
	inputs := a.celRule.Inputs()
	ruleInputs := make([]celscanner.RuleInput, len(inputs))
	for i, input := range inputs {
		ruleInputs[i] = &RuleInputAdapter{input: input}
	}
	return ruleInputs
}

// RuleInputAdapter adapts Input to RuleInput interface
type RuleInputAdapter struct {
	input celscanner.Input
}

func (a *RuleInputAdapter) GetName() string { return a.input.Name() }
func (a *RuleInputAdapter) GetKubeResource() celscanner.KubeResource {
	if a.input.Type() == celscanner.InputTypeKubernetes {
		if kubeSpec, ok := a.input.Spec().(celscanner.KubernetesInputSpec); ok {
			return &KubeResourceAdapter{spec: kubeSpec}
		}
	}
	return &KubeResourceAdapter{spec: nil}
}

// KubeResourceAdapter adapts KubernetesInputSpec to KubeResource interface
type KubeResourceAdapter struct {
	spec celscanner.KubernetesInputSpec
}

func (a *KubeResourceAdapter) GetAPIGroup() string {
	if a.spec != nil {
		return a.spec.ApiGroup()
	}
	return ""
}
func (a *KubeResourceAdapter) GetVersion() string {
	if a.spec != nil {
		return a.spec.Version()
	}
	return "v1"
}
func (a *KubeResourceAdapter) GetResource() string {
	if a.spec != nil {
		return a.spec.ResourceType()
	}
	return ""
}
func (a *KubeResourceAdapter) GetNamespace() string {
	if a.spec != nil {
		return a.spec.Namespace()
	}
	return ""
}
func (a *KubeResourceAdapter) GetName() string {
	if a.spec != nil {
		return a.spec.Name()
	}
	return ""
}

// convertRules converts CelRule slice to Rule slice
func convertRules(celRules []celscanner.CelRule) []celscanner.Rule {
	rules := make([]celscanner.Rule, len(celRules))
	for i, celRule := range celRules {
		rules[i] = &CelRuleAdapter{celRule: celRule}
	}
	return rules
}

// ExampleBasicUsage demonstrates basic usage of the CEL scanner with different input types
func ExampleBasicUsage() {
	log.Println("=== Basic CEL Scanner Usage ===")

	// Create a composite fetcher that supports all input types
	fetcher := inputs.NewCompositeFetcherBuilder().
		WithKubernetesFiles("./testdata"). // Use test data files
		WithFilesystem("/etc").            // Access filesystem
		WithSystem(false).                 // System access (restricted)
		Build()

	// Create a simple logger
	logger := &SimpleLogger{}

	// Create the scanner
	scanner := celscanner.NewScanner(fetcher, logger)

	// Example 1: Check if pods exist
	kubeInput := celscanner.NewKubernetesInput("pods", "", "v1", "pods", "", "")
	podRule := celscanner.NewRule("pods-exist", "pods.items.size() > 0", []celscanner.Input{kubeInput})

	// Example 2: Check configuration file
	configInput := celscanner.NewFileInput("config", "/etc/hostname", "text", false, false)
	configRule := celscanner.NewRule("hostname-set", "size(config) > 0", []celscanner.Input{configInput})

	// Example 3: Check system service
	systemInput := celscanner.NewSystemInput("sshd", "sshd", "", []string{})
	systemRule := celscanner.NewRule("sshd-running", "sshd.status == 'active'", []celscanner.Input{systemInput})

	// Run the scanner
	rules := []celscanner.CelRule{podRule, configRule, systemRule}
	ctx := context.Background()
	config := celscanner.ScanConfig{Rules: convertRules(rules)}
	results, err := scanner.Scan(ctx, config)
	if err != nil {
		log.Printf("Error scanning: %v", err)
		return
	}

	// Display results
	for _, result := range results {
		log.Printf("Rule: %s, Status: %s, Name: %s", result.ID, result.Status, result.Name)
	}
}

// ExampleAdvancedUsage demonstrates advanced usage with complex rules
func ExampleAdvancedUsage() {
	log.Println("=== Advanced CEL Scanner Usage ===")

	// Create fetcher with live Kubernetes API (would need real clients)
	fetcher := inputs.NewCompositeFetcherBuilder().
		WithFilesystem("/etc").
		WithSystem(false).
		Build()

	logger := &SimpleLogger{}
	scanner := celscanner.NewScanner(fetcher, logger)

	// Complex rule that combines multiple inputs
	configInput := celscanner.NewFileInput("nginx_config", "/etc/nginx/nginx.conf", "text", false, false)
	serviceInput := celscanner.NewSystemInput("nginx", "nginx", "", []string{})

	// CEL expression that checks both configuration and service status
	complexRule := celscanner.NewRule("nginx-secure",
		"nginx.status == 'active' && has(nginx_config) && size(nginx_config) > 0",
		[]celscanner.Input{configInput, serviceInput})

	// Directory scanning example
	dirInput := celscanner.NewFileInput("configs", "/etc/ssl/certs", "text", false, false)
	certRule := celscanner.NewRule("ssl-certs-exist",
		"has(configs) && size(configs) > 0",
		[]celscanner.Input{dirInput})

	// Run advanced rules
	rules := []celscanner.CelRule{complexRule, certRule}
	ctx := context.Background()
	config := celscanner.ScanConfig{Rules: convertRules(rules)}
	results, err := scanner.Scan(ctx, config)
	if err != nil {
		log.Printf("Error scanning: %v", err)
		return
	}

	// Display results
	for _, result := range results {
		log.Printf("Rule: %s, Status: %s, Name: %s", result.ID, result.Status, result.Name)
	}
}

// ExampleWithLiveKubernetes demonstrates usage with live Kubernetes API
func ExampleWithLiveKubernetes(kubeClient runtimeclient.Client, kubeClientset kubernetes.Interface) {
	log.Println("=== Live Kubernetes API Usage ===")

	// Create fetcher with live Kubernetes API
	fetcher := inputs.NewCompositeFetcherBuilder().
		WithKubernetes(kubeClient, kubeClientset).
		WithFilesystem("/etc").
		WithSystem(false).
		Build()

	logger := &SimpleLogger{}
	scanner := celscanner.NewScanner(fetcher, logger)

	// Kubernetes security compliance rules
	podInput := celscanner.NewKubernetesInput("pods", "", "v1", "pods", "default", "")
	securityRule := celscanner.NewRule("pod-security-context",
		"pods.items.all(pod, has(pod.spec.securityContext) && pod.spec.securityContext.runAsNonRoot == true)",
		[]celscanner.Input{podInput})

	// Service compliance rule
	serviceInput := celscanner.NewKubernetesInput("services", "", "v1", "services", "default", "")
	serviceRule := celscanner.NewRule("no-nodeport-services",
		"services.items.all(svc, svc.spec.type != 'NodePort')",
		[]celscanner.Input{serviceInput})

	// Combined rule with system check
	systemInput := celscanner.NewSystemInput("kubelet", "kubelet", "", []string{})
	combinedRule := celscanner.NewRule("cluster-health",
		"pods.items.size() > 0 && services.items.size() > 0 && kubelet.status == 'active'",
		[]celscanner.Input{podInput, serviceInput, systemInput})

	// Run compliance checks
	rules := []celscanner.CelRule{securityRule, serviceRule, combinedRule}
	ctx := context.Background()
	config := celscanner.ScanConfig{Rules: convertRules(rules)}
	results, err := scanner.Scan(ctx, config)
	if err != nil {
		log.Printf("Error scanning: %v", err)
		return
	}

	// Display results
	for _, result := range results {
		log.Printf("Rule: %s, Status: %s, Name: %s", result.ID, result.Status, result.Name)
	}
}

// ExampleCustomInputType demonstrates how to add custom input types
func ExampleCustomInputType() {
	log.Println("=== Custom Input Type Usage ===")

	// Create base fetcher
	fetcher := inputs.NewCompositeFetcherBuilder().
		WithFilesystem("/etc").
		WithSystem(false).
		Build()

	// Add custom HTTP input fetcher (hypothetical)
	// httpFetcher := &HTTPFetcher{timeout: 30 * time.Second}
	// fetcher.RegisterCustomFetcher(celscanner.InputTypeHTTP, httpFetcher)

	logger := &SimpleLogger{}
	scanner := celscanner.NewScanner(fetcher, logger)

	// Example with custom input type (would need actual implementation)
	// httpInput := celscanner.NewHTTPInput("api", "https://api.example.com/health", "GET", nil)
	// httpRule := celscanner.NewRule("api-health", "api.status == 200", []celscanner.Input{httpInput})

	// For now, just show regular usage
	configInput := celscanner.NewFileInput("config", "/etc/hostname", "text", false, false)
	rule := celscanner.NewRule("hostname-check", "size(config) > 0", []celscanner.Input{configInput})

	rules := []celscanner.CelRule{rule}
	config := celscanner.ScanConfig{Rules: convertRules(rules)}
	results, err := scanner.Scan(context.Background(), config)
	if err != nil {
		log.Printf("Error scanning: %v", err)
		return
	}

	for _, result := range results {
		log.Printf("Rule: %s, Status: %s", result.ID, result.Status)
	}
}

// ExampleBatchProcessing demonstrates processing multiple rules efficiently
func ExampleBatchProcessing() {
	log.Println("=== Batch Processing Usage ===")

	fetcher := inputs.NewCompositeFetcherBuilder().
		WithKubernetesFiles("./testdata").
		WithFilesystem("/etc").
		WithSystem(false).
		Build()

	logger := &SimpleLogger{}
	scanner := celscanner.NewScanner(fetcher, logger)

	// Create multiple rules for batch processing
	var rules []celscanner.CelRule

	// Kubernetes rules
	podInput := celscanner.NewKubernetesInput("pods", "", "v1", "pods", "", "")
	rules = append(rules, celscanner.NewRule("pods-exist", "pods.items.size() > 0", []celscanner.Input{podInput}))
	rules = append(rules, celscanner.NewRule("pods-have-labels", "pods.items.all(pod, size(pod.metadata.labels) > 0)", []celscanner.Input{podInput}))

	// File system rules
	hostnameInput := celscanner.NewFileInput("hostname", "/etc/hostname", "text", false, false)
	rules = append(rules, celscanner.NewRule("hostname-set", "size(hostname) > 0", []celscanner.Input{hostnameInput}))

	// System rules
	sshInput := celscanner.NewSystemInput("ssh", "sshd", "", []string{})
	rules = append(rules, celscanner.NewRule("ssh-running", "ssh.status == 'active'", []celscanner.Input{sshInput}))

	// Process all rules in batch
	ctx := context.Background()
	config := celscanner.ScanConfig{Rules: convertRules(rules)}
	results, err := scanner.Scan(ctx, config)
	if err != nil {
		log.Printf("Error in batch processing: %v", err)
		return
	}

	// Analyze results
	passed := 0
	failed := 0
	errors := 0

	for _, result := range results {
		switch result.Status {
		case celscanner.CheckResultPass:
			passed++
		case celscanner.CheckResultFail:
			failed++
		case celscanner.CheckResultError:
			errors++
		}
		log.Printf("Rule: %s, Status: %s, Name: %s", result.ID, result.Status, result.Name)
	}

	log.Printf("Batch processing summary: %d passed, %d failed, %d errors", passed, failed, errors)
}

// SimpleLogger implements the Logger interface for examples
type SimpleLogger struct{}

func (l *SimpleLogger) Debug(msg string, args ...interface{}) {
	log.Printf("[DEBUG] "+msg, args...)
}

func (l *SimpleLogger) Info(msg string, args ...interface{}) {
	log.Printf("[INFO] "+msg, args...)
}

func (l *SimpleLogger) Warn(msg string, args ...interface{}) {
	log.Printf("[WARN] "+msg, args...)
}

func (l *SimpleLogger) Error(msg string, args ...interface{}) {
	log.Printf("[ERROR] "+msg, args...)
}

// ExampleErrorHandling demonstrates proper error handling
func ExampleErrorHandling() {
	log.Println("=== Error Handling Usage ===")

	// Create fetcher with potentially failing inputs
	fetcher := inputs.NewCompositeFetcherBuilder().
		WithFilesystem("/nonexistent"). // This will cause errors
		WithSystem(false).
		Build()

	logger := &SimpleLogger{}
	scanner := celscanner.NewScanner(fetcher, logger)

	// Rule that will fail due to missing file
	badInput := celscanner.NewFileInput("missing", "/nonexistent/file.txt", "text", false, false)
	badRule := celscanner.NewRule("missing-file", "size(missing) > 0", []celscanner.Input{badInput})

	// Rule that should work
	goodInput := celscanner.NewSystemInput("uptime", "", "uptime", []string{})
	goodRule := celscanner.NewRule("system-uptime", "has(uptime)", []celscanner.Input{goodInput})

	rules := []celscanner.CelRule{badRule, goodRule}
	ctx := context.Background()
	config := celscanner.ScanConfig{Rules: convertRules(rules)}
	results, err := scanner.Scan(ctx, config)
	if err != nil {
		log.Printf("Scanner error: %v", err)
		// Even if there's an error, some results might be available
	}

	// Process results and handle errors gracefully
	for _, result := range results {
		switch result.Status {
		case celscanner.CheckResultPass:
			log.Printf("✓ Rule %s passed: %s", result.ID, result.Name)
		case celscanner.CheckResultFail:
			log.Printf("✗ Rule %s failed: %s", result.ID, result.Name)
		case celscanner.CheckResultError:
			log.Printf("⚠ Rule %s error: %s", result.ID, result.Name)
		case celscanner.CheckResultNotApplicable:
			log.Printf("⊝ Rule %s skipped: %s", result.ID, result.Name)
		}
	}
}

// Usage demonstration
func RunAllExamples() {
	fmt.Println("Running CEL Scanner Examples...")
	fmt.Println("==============================")

	// Run examples (some may fail if resources don't exist)
	ExampleBasicUsage()
	ExampleAdvancedUsage()
	ExampleBatchProcessing()
	ExampleErrorHandling()
	ExampleCustomInputType()

	fmt.Println("\nExamples completed. Check logs for results.")
}
