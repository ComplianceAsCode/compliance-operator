package utils

import (
	"context"
	"strings"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// operatorManagedPrefixes are label/annotation key prefixes that are managed
// by the compliance-operator and should not be propagated as custom metadata.
var operatorManagedPrefixes = []string{
	"compliance.openshift.io/",
	"complianceoperator.openshift.io/",
	"complianceascode.io/",
}

// IsOperatorManagedKey returns true if the given key is managed by the
// compliance-operator (i.e. starts with a known operator prefix).
func IsOperatorManagedKey(key string) bool {
	for _, prefix := range operatorManagedPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// GetCustomMetadata extracts custom (non-operator-managed) labels and
// annotations from the given maps. It returns new maps containing only
// the entries whose keys do not start with a known operator prefix.
func GetCustomMetadata(labels, annotations map[string]string) (map[string]string, map[string]string) {
	customLabels := filterCustomKeys(labels)
	customAnnotations := filterCustomKeys(annotations)
	return customLabels, customAnnotations
}

// filterCustomKeys returns a new map containing only entries whose keys
// are not operator-managed.
func filterCustomKeys(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	result := make(map[string]string)
	for k, v := range m {
		if !IsOperatorManagedKey(k) {
			result[k] = v
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// RuleMetadataCache provides a lookup from the DNS-friendly rule name
// (the value stored in the compliance.openshift.io/rule annotation) to
// the Rule's custom labels and annotations. This avoids per-result API
// calls during aggregation.
type RuleMetadataCache struct {
	// customLabels maps rule annotation value → custom labels
	customLabels map[string]map[string]string
	// customAnnotations maps rule annotation value → custom annotations
	customAnnotations map[string]map[string]string
}

// NewRuleMetadataCache creates a RuleMetadataCache by listing all Rule
// objects in the given namespace and indexing them by the
// compliance.openshift.io/rule annotation.
func NewRuleMetadataCache(client runtimeclient.Client, namespace string) (*RuleMetadataCache, error) {
	cache := &RuleMetadataCache{
		customLabels:      make(map[string]map[string]string),
		customAnnotations: make(map[string]map[string]string),
	}

	ruleList := &compv1alpha1.RuleList{}
	err := client.List(context.TODO(), ruleList, runtimeclient.InNamespace(namespace))
	if err != nil {
		return nil, err
	}

	for i := range ruleList.Items {
		rule := &ruleList.Items[i]
		ruleAnnotationVal := rule.Annotations[compv1alpha1.RuleIDAnnotationKey]
		if ruleAnnotationVal == "" {
			continue
		}
		customLabels, customAnnotations := GetCustomMetadata(rule.Labels, rule.Annotations)
		if len(customLabels) > 0 || len(customAnnotations) > 0 {
			cache.customLabels[ruleAnnotationVal] = customLabels
			cache.customAnnotations[ruleAnnotationVal] = customAnnotations
		}
	}

	return cache, nil
}

// GetCustomMetadataForRule returns the custom labels and annotations for the
// rule identified by its DNS-friendly name (the value of the
// compliance.openshift.io/rule annotation on the Rule object).
func (c *RuleMetadataCache) GetCustomMetadataForRule(ruleDNSName string) (map[string]string, map[string]string) {
	if c == nil {
		return nil, nil
	}
	return c.customLabels[ruleDNSName], c.customAnnotations[ruleDNSName]
}

// MergeCustomMetadata merges custom labels and annotations into the
// target maps. Custom entries are added only if the key does not already
// exist in the target map, so operator-managed entries take precedence.
func MergeCustomMetadata(targetLabels, customLabels, targetAnnotations, customAnnotations map[string]string) (map[string]string, map[string]string) {
	targetLabels = mergeIfNotExists(targetLabels, customLabels)
	targetAnnotations = mergeIfNotExists(targetAnnotations, customAnnotations)
	return targetLabels, targetAnnotations
}

// mergeIfNotExists adds entries from src into dst only if the key doesn't
// already exist in dst.
func mergeIfNotExists(dst, src map[string]string) map[string]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]string)
	}
	for k, v := range src {
		if _, exists := dst[k]; !exists {
			dst[k] = v
		}
	}
	return dst
}

