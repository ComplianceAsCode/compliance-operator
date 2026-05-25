package manager

import (
	cmpv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	Expect(cmpv1alpha1.SchemeBuilder.AddToScheme(s)).To(Succeed())
	return s
}

var _ = Describe("getCELRulesFromProfile", func() {
	var cs *CelScanner

	celRule := func(name string) *cmpv1alpha1.Rule {
		return &cmpv1alpha1.Rule{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"},
			RulePayload: cmpv1alpha1.RulePayload{
				ID:          name,
				ScannerType: cmpv1alpha1.ScannerTypeCEL,
				Expression:  "true",
				Inputs: []cmpv1alpha1.InputPayload{{
					Name: "pods",
					KubernetesInputSpec: cmpv1alpha1.KubernetesInputSpec{
						APIVersion: "v1",
						Resource:   "pods",
					},
				}},
				FailureReason: "fail",
			},
		}
	}

	oscapRule := func(name string) *cmpv1alpha1.Rule {
		return &cmpv1alpha1.Rule{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"},
			RulePayload: cmpv1alpha1.RulePayload{
				ID:          name,
				ScannerType: cmpv1alpha1.ScannerTypeOpenSCAP,
			},
		}
	}

	It("loads CEL rules from a profile", func() {
		scheme := newTestScheme()
		profile := &cmpv1alpha1.Profile{
			ObjectMeta: metav1.ObjectMeta{Name: "cel-prof", Namespace: "ns"},
			ProfilePayload: cmpv1alpha1.ProfilePayload{
				Rules: []cmpv1alpha1.ProfileRule{"rule-a", "rule-b"},
			},
		}
		ruleA := celRule("rule-a")
		ruleB := celRule("rule-b")

		client := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(profile, ruleA, ruleB).Build()
		cs = &CelScanner{client: client, scheme: scheme}

		rules, err := cs.getCELRulesFromProfile("cel-prof", "ns")
		Expect(err).NotTo(HaveOccurred())
		Expect(rules).To(HaveLen(2))
		Expect(rules[0].scannerRule.Identifier()).To(Equal("rule-a"))
		Expect(rules[1].scannerRule.Identifier()).To(Equal("rule-b"))
	})

	It("skips non-CEL rules", func() {
		scheme := newTestScheme()
		profile := &cmpv1alpha1.Profile{
			ObjectMeta: metav1.ObjectMeta{Name: "mixed-prof", Namespace: "ns"},
			ProfilePayload: cmpv1alpha1.ProfilePayload{
				Rules: []cmpv1alpha1.ProfileRule{"cel-rule", "oscap-rule"},
			},
		}
		client := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(profile, celRule("cel-rule"), oscapRule("oscap-rule")).Build()
		cs = &CelScanner{client: client, scheme: scheme}

		rules, err := cs.getCELRulesFromProfile("mixed-prof", "ns")
		Expect(err).NotTo(HaveOccurred())
		Expect(rules).To(HaveLen(1))
		Expect(rules[0].scannerRule.Identifier()).To(Equal("cel-rule"))
	})

	It("returns error for missing profile", func() {
		scheme := newTestScheme()
		client := fake.NewClientBuilder().WithScheme(scheme).Build()
		cs = &CelScanner{client: client, scheme: scheme}

		_, err := cs.getCELRulesFromProfile("nonexistent", "ns")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("fetching Profile"))
	})

	It("returns error for missing rule referenced by profile", func() {
		scheme := newTestScheme()
		profile := &cmpv1alpha1.Profile{
			ObjectMeta: metav1.ObjectMeta{Name: "prof", Namespace: "ns"},
			ProfilePayload: cmpv1alpha1.ProfilePayload{
				Rules: []cmpv1alpha1.ProfileRule{"missing-rule"},
			},
		}
		client := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(profile).Build()
		cs = &CelScanner{client: client, scheme: scheme}

		_, err := cs.getCELRulesFromProfile("prof", "ns")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not found"))
	})

	It("returns error for CEL rule with empty expression", func() {
		scheme := newTestScheme()
		profile := &cmpv1alpha1.Profile{
			ObjectMeta: metav1.ObjectMeta{Name: "prof", Namespace: "ns"},
			ProfilePayload: cmpv1alpha1.ProfilePayload{
				Rules: []cmpv1alpha1.ProfileRule{"bad-rule"},
			},
		}
		badRule := &cmpv1alpha1.Rule{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-rule", Namespace: "ns"},
			RulePayload: cmpv1alpha1.RulePayload{
				ID:          "bad-rule",
				ScannerType: cmpv1alpha1.ScannerTypeCEL,
				Expression:  "",
				Inputs: []cmpv1alpha1.InputPayload{{
					Name: "pods",
					KubernetesInputSpec: cmpv1alpha1.KubernetesInputSpec{
						APIVersion: "v1", Resource: "pods",
					},
				}},
			},
		}
		client := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(profile, badRule).Build()
		cs = &CelScanner{client: client, scheme: scheme}

		_, err := cs.getCELRulesFromProfile("prof", "ns")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid Rule"))
	})

	It("returns empty slice when profile has only non-CEL rules", func() {
		scheme := newTestScheme()
		profile := &cmpv1alpha1.Profile{
			ObjectMeta: metav1.ObjectMeta{Name: "oscap-prof", Namespace: "ns"},
			ProfilePayload: cmpv1alpha1.ProfilePayload{
				Rules: []cmpv1alpha1.ProfileRule{"oscap-rule"},
			},
		}
		client := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(profile, oscapRule("oscap-rule")).Build()
		cs = &CelScanner{client: client, scheme: scheme}

		rules, err := cs.getCELRulesFromProfile("oscap-prof", "ns")
		Expect(err).NotTo(HaveOccurred())
		Expect(rules).To(BeEmpty())
	})
})

var _ = Describe("getVariablesForProfile", func() {
	var cs *CelScanner

	It("loads variables referenced by profile", func() {
		scheme := newTestScheme()
		profile := &cmpv1alpha1.Profile{
			ObjectMeta: metav1.ObjectMeta{Name: "cel-prof", Namespace: "ns"},
			ProfilePayload: cmpv1alpha1.ProfilePayload{
				Values: []cmpv1alpha1.ProfileValue{"var-timeout", "var-retries"},
			},
		}
		varTimeout := &cmpv1alpha1.Variable{
			ObjectMeta: metav1.ObjectMeta{Name: "var-timeout", Namespace: "ns"},
			VariablePayload: cmpv1alpha1.VariablePayload{
				ID:    "var_timeout",
				Title: "Timeout",
				Value: "30",
			},
		}
		varRetries := &cmpv1alpha1.Variable{
			ObjectMeta: metav1.ObjectMeta{Name: "var-retries", Namespace: "ns"},
			VariablePayload: cmpv1alpha1.VariablePayload{
				ID:    "var_retries",
				Title: "Retries",
				Value: "3",
			},
		}
		client := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(profile, varTimeout, varRetries).Build()
		cs = &CelScanner{client: client, scheme: scheme}

		vars, err := cs.getVariablesForProfile("cel-prof", "ns")
		Expect(err).NotTo(HaveOccurred())
		Expect(vars).To(HaveLen(2))
		Expect(vars[0].Name).To(Equal("var-timeout"))
		Expect(vars[1].Name).To(Equal("var-retries"))
	})

	It("skips variables that are not found", func() {
		scheme := newTestScheme()
		profile := &cmpv1alpha1.Profile{
			ObjectMeta: metav1.ObjectMeta{Name: "prof", Namespace: "ns"},
			ProfilePayload: cmpv1alpha1.ProfilePayload{
				Values: []cmpv1alpha1.ProfileValue{"exists", "missing"},
			},
		}
		existsVar := &cmpv1alpha1.Variable{
			ObjectMeta: metav1.ObjectMeta{Name: "exists", Namespace: "ns"},
			VariablePayload: cmpv1alpha1.VariablePayload{
				ID: "exists", Value: "v",
			},
		}
		client := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(profile, existsVar).Build()
		cs = &CelScanner{client: client, scheme: scheme}

		vars, err := cs.getVariablesForProfile("prof", "ns")
		Expect(err).NotTo(HaveOccurred())
		Expect(vars).To(HaveLen(1))
		Expect(vars[0].Name).To(Equal("exists"))
	})

	It("returns empty when profile has no values", func() {
		scheme := newTestScheme()
		profile := &cmpv1alpha1.Profile{
			ObjectMeta: metav1.ObjectMeta{Name: "no-vals", Namespace: "ns"},
			ProfilePayload: cmpv1alpha1.ProfilePayload{},
		}
		client := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(profile).Build()
		cs = &CelScanner{client: client, scheme: scheme}

		vars, err := cs.getVariablesForProfile("no-vals", "ns")
		Expect(err).NotTo(HaveOccurred())
		Expect(vars).To(BeEmpty())
	})

	It("returns error for missing profile", func() {
		scheme := newTestScheme()
		client := fake.NewClientBuilder().WithScheme(scheme).Build()
		cs = &CelScanner{client: client, scheme: scheme}

		_, err := cs.getVariablesForProfile("nonexistent", "ns")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("fetching Profile"))
	})
})

var _ = Describe("validateCELRulePayload", func() {
	var cs *CelScanner

	BeforeEach(func() {
		cs = &CelScanner{}
	})

	It("passes for valid payload", func() {
		payload := &cmpv1alpha1.RulePayload{
			Expression: "true",
			Inputs: []cmpv1alpha1.InputPayload{{
				Name: "pods",
				KubernetesInputSpec: cmpv1alpha1.KubernetesInputSpec{
					APIVersion: "v1", Resource: "pods",
				},
			}},
			FailureReason: "fail",
		}
		Expect(cs.validateCELRulePayload("test", payload)).To(Succeed())
	})

	It("rejects empty expression", func() {
		payload := &cmpv1alpha1.RulePayload{
			Expression: "",
			Inputs: []cmpv1alpha1.InputPayload{{
				Name: "pods",
				KubernetesInputSpec: cmpv1alpha1.KubernetesInputSpec{
					APIVersion: "v1", Resource: "pods",
				},
			}},
		}
		err := cs.validateCELRulePayload("test", payload)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("expression is empty"))
	})

	It("rejects no inputs", func() {
		payload := &cmpv1alpha1.RulePayload{
			Expression: "true",
			Inputs:     nil,
		}
		err := cs.validateCELRulePayload("test", payload)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("no inputs"))
	})

	It("rejects input with empty name", func() {
		payload := &cmpv1alpha1.RulePayload{
			Expression: "true",
			Inputs: []cmpv1alpha1.InputPayload{{
				Name: "",
				KubernetesInputSpec: cmpv1alpha1.KubernetesInputSpec{
					APIVersion: "v1", Resource: "pods",
				},
			}},
		}
		err := cs.validateCELRulePayload("test", payload)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("empty resource name"))
	})
})

var _ = Describe("celRuleWrapper", func() {
	It("wraps a Rule CR as scanner.Rule", func() {
		rule := &cmpv1alpha1.Rule{
			ObjectMeta: metav1.ObjectMeta{Name: "my-rule"},
			RulePayload: cmpv1alpha1.RulePayload{
				ID:          "my-check",
				ScannerType: cmpv1alpha1.ScannerTypeCEL,
				Expression:  "pods.items.size() > 0",
				Inputs: []cmpv1alpha1.InputPayload{{
					Name: "pods",
					KubernetesInputSpec: cmpv1alpha1.KubernetesInputSpec{
						APIVersion: "v1", Resource: "pods",
					},
				}},
				FailureReason: "no pods",
			},
		}

	w := celRuleWrapper{
		scannerRule: rule,
		payload:     &rule.RulePayload,
	}

	Expect(w.scannerRule.Identifier()).To(Equal("my-rule"))
	Expect(w.payload.Expression).To(Equal("pods.items.size() > 0"))
	Expect(w.payload.FailureReason).To(Equal("no pods"))
	})
})

var _ = Describe("getSelectedCELRules with extends", func() {
	celRule := func(name string) *cmpv1alpha1.Rule {
		return &cmpv1alpha1.Rule{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"},
			RulePayload: cmpv1alpha1.RulePayload{
				ID:          name,
				ScannerType: cmpv1alpha1.ScannerTypeCEL,
				Expression:  "true",
				Inputs: []cmpv1alpha1.InputPayload{{
					Name: "pods",
					KubernetesInputSpec: cmpv1alpha1.KubernetesInputSpec{
						APIVersion: "v1",
						Resource:   "pods",
					},
				}},
				FailureReason: "fail",
			},
		}
	}

	It("loads base profile rules and applies DisableRules", func() {
		scheme := newTestScheme()
		profile := &cmpv1alpha1.Profile{
			ObjectMeta: metav1.ObjectMeta{Name: "cel-prof", Namespace: "ns"},
			ProfilePayload: cmpv1alpha1.ProfilePayload{
				Rules: []cmpv1alpha1.ProfileRule{"rule-a", "rule-b", "rule-c"},
			},
		}
		tp := &cmpv1alpha1.TailoredProfile{
			ObjectMeta: metav1.ObjectMeta{Name: "tp-ext", Namespace: "ns"},
			Spec: cmpv1alpha1.TailoredProfileSpec{
				Extends: "cel-prof",
				DisableRules: []cmpv1alpha1.RuleReferenceSpec{
					{Name: "rule-b"},
				},
			},
		}
		client := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(profile, celRule("rule-a"), celRule("rule-b"), celRule("rule-c"), tp).Build()
		cs := &CelScanner{client: client, scheme: scheme}

		rules, err := cs.getSelectedCELRules(tp)
		Expect(err).NotTo(HaveOccurred())
		Expect(rules).To(HaveLen(2))
		ids := []string{rules[0].scannerRule.Identifier(), rules[1].scannerRule.Identifier()}
		Expect(ids).To(ConsistOf("rule-a", "rule-c"))
	})

	It("extends base profile and adds EnableRules", func() {
		scheme := newTestScheme()
		profile := &cmpv1alpha1.Profile{
			ObjectMeta: metav1.ObjectMeta{Name: "cel-prof", Namespace: "ns"},
			ProfilePayload: cmpv1alpha1.ProfilePayload{
				Rules: []cmpv1alpha1.ProfileRule{"rule-a"},
			},
		}
		tp := &cmpv1alpha1.TailoredProfile{
			ObjectMeta: metav1.ObjectMeta{Name: "tp-add", Namespace: "ns"},
			Spec: cmpv1alpha1.TailoredProfileSpec{
				Extends: "cel-prof",
				EnableRules: []cmpv1alpha1.RuleReferenceSpec{
					{Name: "rule-extra"},
				},
			},
		}
		client := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(profile, celRule("rule-a"), celRule("rule-extra"), tp).Build()
		cs := &CelScanner{client: client, scheme: scheme}

		rules, err := cs.getSelectedCELRules(tp)
		Expect(err).NotTo(HaveOccurred())
		Expect(rules).To(HaveLen(2))
		ids := []string{rules[0].scannerRule.Identifier(), rules[1].scannerRule.Identifier()}
		Expect(ids).To(ConsistOf("rule-a", "rule-extra"))
	})

	It("does not duplicate rules already in base profile", func() {
		scheme := newTestScheme()
		profile := &cmpv1alpha1.Profile{
			ObjectMeta: metav1.ObjectMeta{Name: "cel-prof", Namespace: "ns"},
			ProfilePayload: cmpv1alpha1.ProfilePayload{
				Rules: []cmpv1alpha1.ProfileRule{"rule-a"},
			},
		}
		tp := &cmpv1alpha1.TailoredProfile{
			ObjectMeta: metav1.ObjectMeta{Name: "tp-dup", Namespace: "ns"},
			Spec: cmpv1alpha1.TailoredProfileSpec{
				Extends: "cel-prof",
				EnableRules: []cmpv1alpha1.RuleReferenceSpec{
					{Name: "rule-a"},
				},
			},
		}
		client := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(profile, celRule("rule-a"), tp).Build()
		cs := &CelScanner{client: client, scheme: scheme}

		rules, err := cs.getSelectedCELRules(tp)
		Expect(err).NotTo(HaveOccurred())
		Expect(rules).To(HaveLen(1))
	})
})
