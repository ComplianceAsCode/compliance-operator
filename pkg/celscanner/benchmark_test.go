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

package celscanner

import (
	"context"
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func BenchmarkScanner_SingleRule_SmallCluster(b *testing.B) {
	benchmarkScanner(b, 10, 1, "Single rule on small cluster (10 pods)")
}

func BenchmarkScanner_SingleRule_MediumCluster(b *testing.B) {
	benchmarkScanner(b, 100, 1, "Single rule on medium cluster (100 pods)")
}

func BenchmarkScanner_SingleRule_LargeCluster(b *testing.B) {
	benchmarkScanner(b, 1000, 1, "Single rule on large cluster (1000 pods)")
}

func BenchmarkScanner_MultipleRules_SmallCluster(b *testing.B) {
	benchmarkScanner(b, 10, 5, "Multiple rules (5) on small cluster (10 pods)")
}

func BenchmarkScanner_MultipleRules_MediumCluster(b *testing.B) {
	benchmarkScanner(b, 100, 5, "Multiple rules (5) on medium cluster (100 pods)")
}

func BenchmarkScanner_ComplexRules_MediumCluster(b *testing.B) {
	benchmarkComplexRules(b, 100, "Complex rules on medium cluster (100 pods)")
}

func benchmarkScanner(b *testing.B, podCount int, ruleCount int, description string) {
	// Create mock resources
	mockPods := createLargeMockPodList(podCount)
	mockConfigMaps := createLargeMockConfigMapList(podCount / 10) // 1 configmap per 10 pods

	mockFetcher := &MockResourceFetcher{
		resources: map[string]interface{}{
			"pods":       mockPods,
			"configmaps": mockConfigMaps,
		},
	}

	// Create scanner
	scanner := NewScanner(mockFetcher, &BenchmarkLogger{})

	// Create rules
	rules := make([]Rule, ruleCount)
	for i := 0; i < ruleCount; i++ {
		rules[i] = &TestRule{
			name:        fmt.Sprintf("bench-rule-%d", i),
			id:          fmt.Sprintf("bench-%d", i),
			description: fmt.Sprintf("Benchmark rule %d", i),
			expression:  "pods.items.size() > 0",
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
	}

	config := ScanConfig{
		Rules: rules,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		results, err := scanner.Scan(ctx, config)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
		if len(results) != ruleCount {
			b.Fatalf("Expected %d results, got %d", ruleCount, len(results))
		}
	}

	b.Logf("Benchmark: %s", description)
}

func benchmarkComplexRules(b *testing.B, podCount int, description string) {
	// Create realistic mock resources
	mockPods := createRealisticMockPodList(podCount)
	mockServices := createMockServiceList(podCount / 5) // 1 service per 5 pods
	mockConfigMaps := createLargeMockConfigMapList(podCount / 10)

	mockFetcher := &MockResourceFetcher{
		resources: map[string]interface{}{
			"pods":       mockPods,
			"services":   mockServices,
			"configmaps": mockConfigMaps,
		},
	}

	scanner := NewScanner(mockFetcher, &BenchmarkLogger{})

	// Create complex rules
	rules := []Rule{
		&TestRule{
			name:       "security-compliance",
			expression: `pods.items.all(pod, has(pod.spec.securityContext) && pod.spec.securityContext.runAsNonRoot == true)`,
			inputs: []RuleInput{
				&TestRuleInput{
					name:         "pods",
					kubeResource: &TestKubeResource{name: "pods", resource: "pods"},
				},
			},
		},
		&TestRule{
			name: "resource-limits",
			expression: `pods.items.all(pod, 
				pod.spec.containers.all(container, 
					has(container.resources) && 
					has(container.resources.limits) && 
					has(container.resources.limits.memory)
				)
			)`,
			inputs: []RuleInput{
				&TestRuleInput{
					name:         "pods",
					kubeResource: &TestKubeResource{name: "pods", resource: "pods"},
				},
			},
		},
		&TestRule{
			name: "service-pod-mapping",
			expression: `pods.items.exists(pod, 
				services.items.exists(svc, 
					has(pod.metadata.labels.app) && 
					has(svc.spec.selector.app) && 
					pod.metadata.labels.app == svc.spec.selector.app
				)
			)`,
			inputs: []RuleInput{
				&TestRuleInput{
					name:         "pods",
					kubeResource: &TestKubeResource{name: "pods", resource: "pods"},
				},
				&TestRuleInput{
					name:         "services",
					kubeResource: &TestKubeResource{name: "services", resource: "services"},
				},
			},
		},
		&TestRule{
			name: "configmap-validation",
			expression: `configmaps.items.all(cm, 
				has(cm.data) && 
				size(cm.data) > 0
			)`,
			inputs: []RuleInput{
				&TestRuleInput{
					name:         "configmaps",
					kubeResource: &TestKubeResource{name: "configmaps", resource: "configmaps"},
				},
			},
		},
	}

	config := ScanConfig{
		Rules: rules,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		results, err := scanner.Scan(ctx, config)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
		if len(results) != len(rules) {
			b.Fatalf("Expected %d results, got %d", len(rules), len(results))
		}
	}

	b.Logf("Benchmark: %s", description)
}

func BenchmarkCELExpressionComplexity(b *testing.B) {
	mockPods := createRealisticMockPodList(100)
	mockFetcher := &MockResourceFetcher{
		resources: map[string]interface{}{
			"pods": mockPods,
		},
	}

	expressions := map[string]string{
		"simple":   "pods.items.size() > 0",
		"medium":   "pods.items.all(pod, has(pod.spec.containers))",
		"complex":  `pods.items.all(pod, pod.spec.containers.all(container, has(container.resources) && has(container.resources.limits)))`,
		"advanced": `pods.items.filter(pod, has(pod.spec.securityContext)).all(pod, pod.spec.securityContext.runAsNonRoot == true)`,
	}

	for name, expr := range expressions {
		b.Run(name, func(b *testing.B) {
			scanner := NewScanner(mockFetcher, &BenchmarkLogger{})
			rule := &TestRule{
				name:       "benchmark-rule",
				expression: expr,
				inputs: []RuleInput{
					&TestRuleInput{
						name:         "pods",
						kubeResource: &TestKubeResource{name: "pods", resource: "pods"},
					},
				},
			}

			config := ScanConfig{Rules: []Rule{rule}}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ctx := context.Background()
				_, err := scanner.Scan(ctx, config)
				if err != nil {
					b.Fatalf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func BenchmarkResourceFetching(b *testing.B) {
	sizes := []int{10, 100, 1000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("pods-%d", size), func(b *testing.B) {
			mockPods := createLargeMockPodList(size)
			mockFetcher := &MockResourceFetcher{
				resources: map[string]interface{}{
					"pods": mockPods,
				},
			}

			rule := &TestRule{
				name:       "fetch-test",
				expression: "true", // Simple expression to focus on fetching
				inputs: []RuleInput{
					&TestRuleInput{
						name:         "pods",
						kubeResource: &TestKubeResource{name: "pods", resource: "pods"},
					},
				},
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ctx := context.Background()
				_, _, err := mockFetcher.FetchResources(ctx, rule, nil)
				if err != nil {
					b.Fatalf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// Helper functions for benchmark data creation

func createLargeMockPodList(count int) *unstructured.UnstructuredList {
	podList := &unstructured.UnstructuredList{
		Items: make([]unstructured.Unstructured, count),
	}

	for i := 0; i < count; i++ {
		pod := unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata": map[string]interface{}{
					"name":      fmt.Sprintf("pod-%d", i),
					"namespace": "default",
					"labels": map[string]interface{}{
						"app": fmt.Sprintf("app-%d", i%10), // 10 different apps
					},
				},
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"name":  "container-0",
							"image": "nginx:latest",
						},
					},
				},
				"status": map[string]interface{}{
					"phase": "Running",
				},
			},
		}
		podList.Items[i] = pod
	}

	return podList
}

func createRealisticMockPodList(count int) *unstructured.UnstructuredList {
	podList := &unstructured.UnstructuredList{
		Items: make([]unstructured.Unstructured, count),
	}

	for i := 0; i < count; i++ {
		runAsNonRoot := i%3 != 0 // 2/3 of pods run as non-root
		hasLimits := i%2 == 0    // 1/2 of pods have resource limits

		containers := []interface{}{
			map[string]interface{}{
				"name":  "main-container",
				"image": fmt.Sprintf("app:v%d", i%5),
				"securityContext": map[string]interface{}{
					"runAsNonRoot": runAsNonRoot,
				},
			},
		}

		if hasLimits {
			containers[0].(map[string]interface{})["resources"] = map[string]interface{}{
				"limits": map[string]interface{}{
					"cpu":    "500m",
					"memory": "512Mi",
				},
				"requests": map[string]interface{}{
					"cpu":    "250m",
					"memory": "256Mi",
				},
			}
		}

		pod := unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata": map[string]interface{}{
					"name":      fmt.Sprintf("realistic-pod-%d", i),
					"namespace": "default",
					"labels": map[string]interface{}{
						"app":     fmt.Sprintf("app-%d", i%10),
						"version": fmt.Sprintf("v%d", i%3),
					},
				},
				"spec": map[string]interface{}{
					"containers": containers,
					"securityContext": map[string]interface{}{
						"runAsNonRoot": runAsNonRoot,
					},
				},
				"status": map[string]interface{}{
					"phase": "Running",
				},
			},
		}
		podList.Items[i] = pod
	}

	return podList
}

func createLargeMockConfigMapList(count int) *unstructured.UnstructuredList {
	configMapList := &unstructured.UnstructuredList{
		Items: make([]unstructured.Unstructured, count),
	}

	for i := 0; i < count; i++ {
		cm := unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "ConfigMap",
				"metadata": map[string]interface{}{
					"name":      fmt.Sprintf("config-%d", i),
					"namespace": "default",
				},
				"data": map[string]interface{}{
					"config.yaml": fmt.Sprintf("app: app-%d\nversion: v1.0", i),
					"app.json":    fmt.Sprintf(`{"name": "app-%d", "enabled": true}`, i),
				},
			},
		}
		configMapList.Items[i] = cm
	}

	return configMapList
}

func createMockServiceList(count int) *unstructured.UnstructuredList {
	serviceList := &unstructured.UnstructuredList{
		Items: make([]unstructured.Unstructured, count),
	}

	for i := 0; i < count; i++ {
		svc := unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Service",
				"metadata": map[string]interface{}{
					"name":      fmt.Sprintf("service-%d", i),
					"namespace": "default",
				},
				"spec": map[string]interface{}{
					"selector": map[string]interface{}{
						"app": fmt.Sprintf("app-%d", i%10),
					},
					"ports": []interface{}{
						map[string]interface{}{
							"port":       80,
							"targetPort": 8080,
						},
					},
					"type": "ClusterIP",
				},
			},
		}
		serviceList.Items[i] = svc
	}

	return serviceList
}

// BenchmarkLogger is a no-op logger for benchmarks
type BenchmarkLogger struct{}

func (l *BenchmarkLogger) Debug(msg string, args ...interface{}) {}
func (l *BenchmarkLogger) Info(msg string, args ...interface{})  {}
func (l *BenchmarkLogger) Warn(msg string, args ...interface{})  {}
func (l *BenchmarkLogger) Error(msg string, args ...interface{}) {}
