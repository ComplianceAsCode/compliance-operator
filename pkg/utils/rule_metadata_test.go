package utils

import (
	"testing"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestIsOperatorManagedKey(t *testing.T) {
	tests := []struct {
		key      string
		expected bool
	}{
		{"compliance.openshift.io/scan-name", true},
		{"compliance.openshift.io/check-status", true},
		{"complianceoperator.openshift.io/scan-script", true},
		{"complianceascode.io/depends-on", true},
		{"weakness_score", false},
		{"break_severity", false},
		{"internal-id", false},
		{"custom.example.com/rating", false},
		{"app.kubernetes.io/name", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			result := IsOperatorManagedKey(tt.key)
			if result != tt.expected {
				t.Errorf("IsOperatorManagedKey(%q) = %v, want %v", tt.key, result, tt.expected)
			}
		})
	}
}

func TestGetCustomMetadata(t *testing.T) {
	t.Run("mixed labels and annotations", func(t *testing.T) {
		labels := map[string]string{
			"compliance.openshift.io/profile-bundle": "ocp4",
			"weakness_score":                         "high",
			"break_severity":                         "critical",
		}
		annotations := map[string]string{
			"compliance.openshift.io/rule":     "my-rule",
			"complianceascode.io/depends-on":   "other-rule",
			"internal-id":                      "SEC-12345",
			"custom.example.com/audit-contact": "security-team",
		}

		customLabels, customAnnotations := GetCustomMetadata(labels, annotations)

		if len(customLabels) != 2 {
			t.Errorf("expected 2 custom labels, got %d: %v", len(customLabels), customLabels)
		}
		if customLabels["weakness_score"] != "high" {
			t.Errorf("expected weakness_score=high, got %q", customLabels["weakness_score"])
		}
		if customLabels["break_severity"] != "critical" {
			t.Errorf("expected break_severity=critical, got %q", customLabels["break_severity"])
		}

		if len(customAnnotations) != 2 {
			t.Errorf("expected 2 custom annotations, got %d: %v", len(customAnnotations), customAnnotations)
		}
		if customAnnotations["internal-id"] != "SEC-12345" {
			t.Errorf("expected internal-id=SEC-12345, got %q", customAnnotations["internal-id"])
		}
		if customAnnotations["custom.example.com/audit-contact"] != "security-team" {
			t.Errorf("expected custom.example.com/audit-contact=security-team, got %q", customAnnotations["custom.example.com/audit-contact"])
		}
	})

	t.Run("no custom metadata", func(t *testing.T) {
		labels := map[string]string{
			"compliance.openshift.io/profile-bundle": "ocp4",
		}
		annotations := map[string]string{
			"compliance.openshift.io/rule": "my-rule",
		}

		customLabels, customAnnotations := GetCustomMetadata(labels, annotations)
		if customLabels != nil {
			t.Errorf("expected nil custom labels, got %v", customLabels)
		}
		if customAnnotations != nil {
			t.Errorf("expected nil custom annotations, got %v", customAnnotations)
		}
	})

	t.Run("nil maps", func(t *testing.T) {
		customLabels, customAnnotations := GetCustomMetadata(nil, nil)
		if customLabels != nil {
			t.Errorf("expected nil custom labels, got %v", customLabels)
		}
		if customAnnotations != nil {
			t.Errorf("expected nil custom annotations, got %v", customAnnotations)
		}
	})

	t.Run("all custom metadata", func(t *testing.T) {
		labels := map[string]string{
			"team":     "security",
			"priority": "high",
		}
		annotations := map[string]string{
			"note": "requires review",
		}

		customLabels, customAnnotations := GetCustomMetadata(labels, annotations)
		if len(customLabels) != 2 {
			t.Errorf("expected 2 custom labels, got %d", len(customLabels))
		}
		if len(customAnnotations) != 1 {
			t.Errorf("expected 1 custom annotation, got %d", len(customAnnotations))
		}
	})
}

func TestMergeCustomMetadata(t *testing.T) {
	t.Run("merge into existing maps", func(t *testing.T) {
		targetLabels := map[string]string{
			"compliance.openshift.io/scan-name": "my-scan",
			"existing-label":                    "existing-value",
		}
		customLabels := map[string]string{
			"weakness_score": "high",
			"existing-label": "should-not-overwrite", // should not overwrite
		}
		targetAnnotations := map[string]string{
			"compliance.openshift.io/rule": "my-rule",
		}
		customAnnotations := map[string]string{
			"internal-id": "SEC-12345",
		}

		resultLabels, resultAnnotations := MergeCustomMetadata(targetLabels, customLabels, targetAnnotations, customAnnotations)

		if resultLabels["weakness_score"] != "high" {
			t.Errorf("expected weakness_score=high, got %q", resultLabels["weakness_score"])
		}
		if resultLabels["existing-label"] != "existing-value" {
			t.Errorf("existing-label should not be overwritten, got %q", resultLabels["existing-label"])
		}
		if resultAnnotations["internal-id"] != "SEC-12345" {
			t.Errorf("expected internal-id=SEC-12345, got %q", resultAnnotations["internal-id"])
		}
	})

	t.Run("merge into nil maps", func(t *testing.T) {
		customLabels := map[string]string{"weakness_score": "high"}
		customAnnotations := map[string]string{"internal-id": "SEC-12345"}

		resultLabels, resultAnnotations := MergeCustomMetadata(nil, customLabels, nil, customAnnotations)

		if resultLabels["weakness_score"] != "high" {
			t.Errorf("expected weakness_score=high, got %q", resultLabels["weakness_score"])
		}
		if resultAnnotations["internal-id"] != "SEC-12345" {
			t.Errorf("expected internal-id=SEC-12345, got %q", resultAnnotations["internal-id"])
		}
	})

	t.Run("merge nil custom into existing", func(t *testing.T) {
		targetLabels := map[string]string{"existing": "value"}

		resultLabels, _ := MergeCustomMetadata(targetLabels, nil, nil, nil)

		if len(resultLabels) != 1 || resultLabels["existing"] != "value" {
			t.Errorf("expected original map unchanged, got %v", resultLabels)
		}
	})
}

func TestNewRuleMetadataCache(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := compv1alpha1.SchemeBuilder.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	t.Run("cache with custom metadata on rules", func(t *testing.T) {
		rule1 := &compv1alpha1.Rule{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ocp4-accounts-no-clusterrolebindings",
				Namespace: "openshift-compliance",
				Labels: map[string]string{
					"compliance.openshift.io/profile-bundle": "ocp4",
					"weakness_score":                         "high",
				},
				Annotations: map[string]string{
					"compliance.openshift.io/rule": "accounts-no-clusterrolebindings",
					"internal-id":                  "SEC-100",
				},
			},
			RulePayload: compv1alpha1.RulePayload{
				ID:    "xccdf_org.ssgproject.content_rule_accounts_no_clusterrolebindings",
				Title: "Test Rule",
			},
		}

		rule2 := &compv1alpha1.Rule{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ocp4-api-server-encryption",
				Namespace: "openshift-compliance",
				Labels: map[string]string{
					"compliance.openshift.io/profile-bundle": "ocp4",
				},
				Annotations: map[string]string{
					"compliance.openshift.io/rule": "api-server-encryption",
				},
			},
			RulePayload: compv1alpha1.RulePayload{
				ID:    "xccdf_org.ssgproject.content_rule_api_server_encryption",
				Title: "Test Rule 2",
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithRuntimeObjects(rule1, rule2).
			Build()

		cache, err := NewRuleMetadataCache(client, "openshift-compliance")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Rule 1 has custom metadata
		customLabels, customAnnotations := cache.GetCustomMetadataForRule("accounts-no-clusterrolebindings")
		if customLabels["weakness_score"] != "high" {
			t.Errorf("expected weakness_score=high, got %v", customLabels)
		}
		if customAnnotations["internal-id"] != "SEC-100" {
			t.Errorf("expected internal-id=SEC-100, got %v", customAnnotations)
		}

		// Rule 2 has no custom metadata
		customLabels2, customAnnotations2 := cache.GetCustomMetadataForRule("api-server-encryption")
		if customLabels2 != nil {
			t.Errorf("expected nil custom labels for rule 2, got %v", customLabels2)
		}
		if customAnnotations2 != nil {
			t.Errorf("expected nil custom annotations for rule 2, got %v", customAnnotations2)
		}

		// Non-existent rule
		customLabels3, customAnnotations3 := cache.GetCustomMetadataForRule("non-existent")
		if customLabels3 != nil {
			t.Errorf("expected nil custom labels for non-existent rule, got %v", customLabels3)
		}
		if customAnnotations3 != nil {
			t.Errorf("expected nil custom annotations for non-existent rule, got %v", customAnnotations3)
		}
	})

	t.Run("nil cache is safe", func(t *testing.T) {
		var cache *RuleMetadataCache
		customLabels, customAnnotations := cache.GetCustomMetadataForRule("any-rule")
		if customLabels != nil || customAnnotations != nil {
			t.Errorf("expected nil from nil cache")
		}
	})

	t.Run("cache with empty namespace", func(t *testing.T) {
		client := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		cache, err := NewRuleMetadataCache(client, "openshift-compliance")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		customLabels, customAnnotations := cache.GetCustomMetadataForRule("any-rule")
		if customLabels != nil || customAnnotations != nil {
			t.Errorf("expected nil from empty cache")
		}
	})
}

func TestRuleMetadataCacheIntegration(t *testing.T) {
	// This test simulates the full flow: a Rule with custom metadata
	// and verifying that the cache correctly indexes and retrieves it.
	scheme := runtime.NewScheme()
	if err := compv1alpha1.SchemeBuilder.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	// Simulate a user-modified Rule with custom labels and annotations
	rule := &compv1alpha1.Rule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ocp4-accounts-no-0clusterrolebindings-default-service-account",
			Namespace: "openshift-compliance",
			Labels: map[string]string{
				"compliance.openshift.io/profile-bundle": "ocp4",
				"weakness_score":                         "9.5",
				"break_severity":                         "critical",
			},
			Annotations: map[string]string{
				"compliance.openshift.io/rule":     "accounts-no-0clusterrolebindings-default-service-account",
				"compliance.openshift.io/profiles": "ocp4-cis",
				"internal-id":                      "SEC-001",
				"custom-audit-ref":                 "AUDIT-2026-Q1",
			},
		},
		RulePayload: compv1alpha1.RulePayload{
			ID:    "xccdf_org.ssgproject.content_rule_accounts_no_0clusterrolebindings_default_service_account",
			Title: "Test Rule",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(rule).
		Build()

	cache, err := NewRuleMetadataCache(client, "openshift-compliance")
	if err != nil {
		t.Fatalf("unexpected error building cache: %v", err)
	}

	// Simulate the aggregator looking up custom metadata using the DNS-friendly name
	ruleDNSName := IDToDNSFriendlyName("xccdf_org.ssgproject.content_rule_accounts_no_0clusterrolebindings_default_service_account")
	customLabels, customAnnotations := cache.GetCustomMetadataForRule(ruleDNSName)

	// Verify custom labels were extracted (only non-operator ones)
	if customLabels["weakness_score"] != "9.5" {
		t.Errorf("expected weakness_score=9.5, got %q", customLabels["weakness_score"])
	}
	if customLabels["break_severity"] != "critical" {
		t.Errorf("expected break_severity=critical, got %q", customLabels["break_severity"])
	}
	if _, exists := customLabels["compliance.openshift.io/profile-bundle"]; exists {
		t.Error("operator-managed label should not be in custom labels")
	}

	// Verify custom annotations were extracted (only non-operator ones)
	if customAnnotations["internal-id"] != "SEC-001" {
		t.Errorf("expected internal-id=SEC-001, got %q", customAnnotations["internal-id"])
	}
	if customAnnotations["custom-audit-ref"] != "AUDIT-2026-Q1" {
		t.Errorf("expected custom-audit-ref=AUDIT-2026-Q1, got %q", customAnnotations["custom-audit-ref"])
	}
	if _, exists := customAnnotations["compliance.openshift.io/rule"]; exists {
		t.Error("operator-managed annotation should not be in custom annotations")
	}
	if _, exists := customAnnotations["compliance.openshift.io/profiles"]; exists {
		t.Error("operator-managed annotation should not be in custom annotations")
	}

	// Simulate merging into check result labels/annotations
	checkResultLabels := map[string]string{
		"compliance.openshift.io/scan-name":    "my-scan",
		"compliance.openshift.io/check-status": "FAIL",
	}
	checkResultAnnotations := map[string]string{
		"compliance.openshift.io/rule": "accounts-no-0clusterrolebindings-default-service-account",
	}

	mergedLabels, mergedAnnotations := MergeCustomMetadata(
		checkResultLabels, customLabels,
		checkResultAnnotations, customAnnotations,
	)

	// Verify merged result
	if mergedLabels["weakness_score"] != "9.5" {
		t.Errorf("expected weakness_score=9.5 in merged labels, got %q", mergedLabels["weakness_score"])
	}
	if mergedLabels["compliance.openshift.io/scan-name"] != "my-scan" {
		t.Error("operator label should be preserved")
	}
	if mergedAnnotations["internal-id"] != "SEC-001" {
		t.Errorf("expected internal-id in merged annotations, got %q", mergedAnnotations["internal-id"])
	}
	if mergedAnnotations["compliance.openshift.io/rule"] != "accounts-no-0clusterrolebindings-default-service-account" {
		t.Error("operator annotation should be preserved")
	}

}

