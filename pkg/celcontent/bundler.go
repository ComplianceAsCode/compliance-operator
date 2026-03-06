package celcontent

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

// CELRuleContent represents a single CEL rule definition in source form.
// Each rule lives in its own YAML file inside a rules directory.
type CELRuleContent struct {
	Name          string              `json:"name"`
	ID            string              `json:"id"`
	Title         string              `json:"title"`
	Description   string              `json:"description,omitempty"`
	Rationale     string              `json:"rationale,omitempty"`
	Severity      string              `json:"severity"`
	CheckType     string              `json:"checkType"`
	Expression    string              `json:"expression"`
	Inputs        []InputPayload      `json:"inputs"`
	FailureReason string              `json:"failureReason,omitempty"`
	Instructions  string              `json:"instructions,omitempty"`
	Variables     []string            `json:"variables,omitempty"`
	Controls      map[string][]string `json:"controls,omitempty"`
}

// InputPayload mirrors cmpv1alpha1.InputPayload without importing the full API
// package, keeping this utility free of operator dependencies.
type InputPayload struct {
	Name                string              `json:"name"`
	KubernetesInputSpec KubernetesInputSpec `json:"kubernetesInputSpec"`
}

// KubernetesInputSpec mirrors cmpv1alpha1.KubernetesInputSpec.
type KubernetesInputSpec struct {
	Group             string `json:"group,omitempty"`
	APIVersion        string `json:"apiVersion"`
	Resource          string `json:"resource"`
	ResourceName      string `json:"resourceName,omitempty"`
	ResourceNamespace string `json:"resourceNamespace,omitempty"`
}

// CELProfileContent represents a single CEL profile definition in source form.
// Each profile lives in its own YAML file inside a profiles directory.
type CELProfileContent struct {
	Name        string   `json:"name"`
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	ProductType string   `json:"productType,omitempty"`
	ProductName string   `json:"productName,omitempty"`
	Rules       []string `json:"rules"`
	Values      []string `json:"values,omitempty"`
}

// CELBundleContent is the combined output: all rules and profiles in a single
// structure ready to be serialized as a bundle YAML.
type CELBundleContent struct {
	Rules    []CELRuleContent    `json:"rules"`
	Profiles []CELProfileContent `json:"profiles"`
}

// BundleFromDirs reads individual CEL rule files from rulesDir and profile
// files from profilesDir, validates references, and returns a CELBundleContent.
// Files must have .yaml or .yml extension.
func BundleFromDirs(rulesDir, profilesDir string) (*CELBundleContent, error) {
	rules, err := loadRules(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("loading rules from %s: %w", rulesDir, err)
	}

	profiles, err := loadProfiles(profilesDir)
	if err != nil {
		return nil, fmt.Errorf("loading profiles from %s: %w", profilesDir, err)
	}

	ruleNames := make(map[string]bool, len(rules))
	for _, r := range rules {
		if ruleNames[r.Name] {
			return nil, fmt.Errorf("duplicate rule name: %s", r.Name)
		}
		ruleNames[r.Name] = true
	}

	for _, p := range profiles {
		for _, ruleName := range p.Rules {
			if !ruleNames[ruleName] {
				return nil, fmt.Errorf("profile %q references unknown rule %q", p.Name, ruleName)
			}
		}
	}

	return &CELBundleContent{
		Rules:    rules,
		Profiles: profiles,
	}, nil
}

// BundleToYAML serializes a CELBundleContent to YAML bytes.
func BundleToYAML(bundle *CELBundleContent) ([]byte, error) {
	return yaml.Marshal(bundle)
}

// BundleToFile is a convenience that calls BundleFromDirs and writes the
// resulting YAML to outputPath.
func BundleToFile(rulesDir, profilesDir, outputPath string) error {
	bundle, err := BundleFromDirs(rulesDir, profilesDir)
	if err != nil {
		return err
	}
	data, err := BundleToYAML(bundle)
	if err != nil {
		return fmt.Errorf("marshaling bundle: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("writing bundle to %s: %w", outputPath, err)
	}
	return nil
}

func loadRules(dir string) ([]CELRuleContent, error) {
	files, err := listYAMLFiles(dir)
	if err != nil {
		return nil, err
	}

	rules := make([]CELRuleContent, 0, len(files))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", f, err)
		}
		var rule CELRuleContent
		if err := yaml.Unmarshal(data, &rule); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", f, err)
		}
		if rule.Name == "" {
			return nil, fmt.Errorf("rule in %s has no name", f)
		}
		if rule.Expression == "" {
			return nil, fmt.Errorf("rule %q in %s has no expression", rule.Name, f)
		}
		if len(rule.Inputs) == 0 {
			return nil, fmt.Errorf("rule %q in %s has no inputs", rule.Name, f)
		}
		rules = append(rules, rule)
	}

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Name < rules[j].Name
	})
	return rules, nil
}

func loadProfiles(dir string) ([]CELProfileContent, error) {
	files, err := listYAMLFiles(dir)
	if err != nil {
		return nil, err
	}

	profiles := make([]CELProfileContent, 0, len(files))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", f, err)
		}
		var profile CELProfileContent
		if err := yaml.Unmarshal(data, &profile); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", f, err)
		}
		if profile.Name == "" {
			return nil, fmt.Errorf("profile in %s has no name", f)
		}
		if len(profile.Rules) == 0 {
			return nil, fmt.Errorf("profile %q in %s has no rules", profile.Name, f)
		}
		profiles = append(profiles, profile)
	}

	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Name < profiles[j].Name
	})
	return profiles, nil
}

func listYAMLFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory %s: %w", dir, err)
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}
