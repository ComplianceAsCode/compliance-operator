package profileparser

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	cmpv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils/celvalidation"
	"github.com/ComplianceAsCode/compliance-operator/pkg/xccdf"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/storage/names"
	"sigs.k8s.io/yaml"
)

// CELBundleContent represents the top-level structure of a CEL content YAML file.
// It contains CEL-based rules and profiles that are shipped alongside XCCDF content.
// Variables are not defined here; CEL rules reuse Variable CRs created from the
// XCCDF DataStream in the same ProfileBundle. A future iteration may add a
// variables section for bundles that ship CEL-only content without XCCDF.
type CELBundleContent struct {
	Rules    []CELRuleContent    `json:"rules"`
	Profiles []CELProfileContent `json:"profiles"`
}

// CELRuleContent represents a single CEL rule definition in the content file.
type CELRuleContent struct {
	Name          string                       `json:"name"`
	ID            string                       `json:"id"`
	Title         string                       `json:"title"`
	Description   string                       `json:"description,omitempty"`
	Rationale     string                       `json:"rationale,omitempty"`
	Severity      string                       `json:"severity"`
	CheckType     string                       `json:"checkType"`
	Expression    string                       `json:"expression"`
	Inputs        []cmpv1alpha1.InputPayload    `json:"inputs"`
	FailureReason string                       `json:"failureReason,omitempty"`
	Instructions  string                       `json:"instructions,omitempty"`
	// Variables lists the Variable CR names that this rule depends on.
	// Sets the compliance.openshift.io/rule-variable annotation.
	// +optional
	Variables     []string                     `json:"variables,omitempty"`
	// Controls maps compliance standard names to their control IDs.
	// Sets control.compliance.openshift.io/<standard> and RHACM annotations.
	// Example: {"NIST-800-53": ["IA-5(f)", "CM-6(a)"], "CIS-OCP": ["1.2.3"]}
	// +optional
	Controls      map[string][]string          `json:"controls,omitempty"`
}

// CELProfileContent represents a single CEL profile definition in the content file.
type CELProfileContent struct {
	Name        string   `json:"name"`
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	ProductType string   `json:"productType,omitempty"`
	ProductName string   `json:"productName,omitempty"`
	Rules       []string `json:"rules"`
	// Values lists the Variable CR names this profile references.
	// Stored in Profile.Values so the CEL scanner can load them.
	// +optional
	Values      []string `json:"values,omitempty"`
}

// ParseCELBundle reads a CEL content YAML file and creates Rule and Profile CRs.
// CEL rules are validated at parse time using celvalidation.ValidateCELRule.
func ParseCELBundle(celPath string, pb *cmpv1alpha1.ProfileBundle, pcfg *ParserConfig) error {
	data, err := os.ReadFile(celPath)
	if err != nil {
		return fmt.Errorf("reading CEL content file: %w", err)
	}

	var bundle CELBundleContent
	if err := yaml.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("parsing CEL content YAML: %w", err)
	}

	if len(bundle.Rules) == 0 && len(bundle.Profiles) == 0 {
		log.Info("CEL content file is empty, nothing to parse", "path", celPath)
		return nil
	}

	// Build a reverse mapping from rule name -> list of profile names that include it.
	// This mirrors the RuleProfileAnnotationKey set on XCCDF rules.
	ruleToProfiles := make(map[string][]string)
	for i := range bundle.Profiles {
		prefixedProfileName := GetPrefixedName(pb.Name, bundle.Profiles[i].Name)
		for _, ruleName := range bundle.Profiles[i].Rules {
			ruleToProfiles[ruleName] = append(ruleToProfiles[ruleName], prefixedProfileName)
		}
	}

	nonce := names.SimpleNameGenerator.GenerateName(fmt.Sprintf("pb-cel-%s", pb.Name))

	errChan := make(chan error)
	done := make(chan string)
	var wg sync.WaitGroup
	wg.Add(2)

	// Parse CEL rules
	go func() {
		defer wg.Done()
		for i := range bundle.Rules {
			celRule := &bundle.Rules[i]

			rulePayload := cmpv1alpha1.RulePayload{
				ID:            celRule.ID,
				Title:         celRule.Title,
				Description:   celRule.Description,
				Rationale:     celRule.Rationale,
				Severity:      celRule.Severity,
				CheckType:     celRule.CheckType,
				ScannerType:   cmpv1alpha1.ScannerTypeCEL,
				Expression:    celRule.Expression,
				Inputs:        celRule.Inputs,
				FailureReason: celRule.FailureReason,
				Instructions:  celRule.Instructions,
			}

			// Validate CEL expression at parse time
			if err := celvalidation.ValidateCELRule(celRule.Name, &rulePayload); err != nil {
				errChan <- fmt.Errorf("CEL rule '%s' validation failed: %w", celRule.Name, err)
				return
			}

			annotations := map[string]string{
				cmpv1alpha1.RuleIDAnnotationKey: celRule.Name,
			}
			// Set which profiles reference this rule (same as XCCDF rules)
			if profiles, ok := ruleToProfiles[celRule.Name]; ok {
				annotations[cmpv1alpha1.RuleProfileAnnotationKey] = strings.Join(profiles, ",")
			}
			// Set compliance standard/control annotations (mirrors XCCDF reference parsing)
			for std, ctrls := range celRule.Controls {
				for _, ctrl := range ctrls {
					profileOperatorFormatter(annotations, std, ctrl)
					rhacmFormatter(annotations, std, ctrl)
				}
			}
			// Set rule-variable annotation listing which Variable CRs this rule depends on
			if len(celRule.Variables) > 0 {
				annotations[cmpv1alpha1.RuleVariableAnnotationKey] = strings.Join(celRule.Variables, ",")
			}

			rule := &cmpv1alpha1.Rule{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Rule",
					APIVersion: cmpv1alpha1.SchemeGroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:        celRule.Name,
					Namespace:   pb.Namespace,
					Annotations: annotations,
				},
				RulePayload: rulePayload,
			}

			annotateWithNonce(rule, nonce)

			if err := parseAction(rule, "Rule", pb, pcfg, func(found, updated interface{}) error {
				foundRule, ok := found.(*cmpv1alpha1.Rule)
				if !ok {
					return fmt.Errorf("unexpected type")
				}
				updatedRule, ok := updated.(*cmpv1alpha1.Rule)
				if !ok {
					return fmt.Errorf("unexpected type")
				}
				foundRule.Annotations = updatedRule.Annotations
				foundRule.RulePayload = *updatedRule.RulePayload.DeepCopy()
				return pcfg.Client.Update(context.TODO(), foundRule)
			}); err != nil {
				errChan <- err
				return
			}
		}
	}()

	// Parse CEL profiles
	go func() {
		defer wg.Done()
		for i := range bundle.Profiles {
			celProfile := &bundle.Profiles[i]

			productType := celProfile.ProductType
			if productType == "" {
				productType = string(cmpv1alpha1.ScanTypePlatform)
			}

			selectedRules := make([]cmpv1alpha1.ProfileRule, 0, len(celProfile.Rules))
			for _, ruleName := range celProfile.Rules {
				prefixedRuleName := GetPrefixedName(pb.Name, ruleName)
				selectedRules = append(selectedRules, cmpv1alpha1.NewProfileRule(prefixedRuleName))
			}

			selectedValues := make([]cmpv1alpha1.ProfileValue, 0, len(celProfile.Values))
			for _, valName := range celProfile.Values {
				selectedValues = append(selectedValues, cmpv1alpha1.ProfileValue(valName))
			}

			profileGuid := xccdf.GetProfileUniqueIDFromBundleName(pb.Name, celProfile.Name)

			profile := &cmpv1alpha1.Profile{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Profile",
					APIVersion: cmpv1alpha1.SchemeGroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      celProfile.Name,
					Namespace: pb.Namespace,
					Annotations: map[string]string{
						cmpv1alpha1.ProductTypeAnnotation: productType,
						cmpv1alpha1.ScannerTypeAnnotation: string(cmpv1alpha1.ScannerTypeCEL),
					},
					Labels: map[string]string{
						cmpv1alpha1.ProfileGuidLabel: profileGuid,
					},
				},
				ProfilePayload: cmpv1alpha1.ProfilePayload{
					ID:          celProfile.ID,
					Title:       celProfile.Title,
					Description: celProfile.Description,
					Rules:       selectedRules,
					Values:      selectedValues,
				},
			}
			if celProfile.ProductName != "" {
				profile.Annotations[cmpv1alpha1.ProductAnnotation] = celProfile.ProductName
			}

			annotateWithNonce(profile, nonce)

			if err := parseAction(profile, "Profile", pb, pcfg, func(found, updated interface{}) error {
				foundProfile, ok := found.(*cmpv1alpha1.Profile)
				if !ok {
					return fmt.Errorf("unexpected type")
				}
				updatedProfile, ok := updated.(*cmpv1alpha1.Profile)
				if !ok {
					return fmt.Errorf("unexpected type")
				}
				foundProfile.Annotations = updatedProfile.Annotations
				foundProfile.ProfilePayload = *updatedProfile.ProfilePayload.DeepCopy()
				return pcfg.Client.Update(context.TODO(), foundProfile)
			}); err != nil {
				errChan <- err
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case err := <-errChan:
		close(errChan)
		return err
	}
}
