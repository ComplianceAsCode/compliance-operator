package v1alpha1

import (
	"github.com/ComplianceAsCode/compliance-sdk/pkg/scanner"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("RulePayload shared helpers", func() {
	var payload RulePayload

	BeforeEach(func() {
		payload = RulePayload{
			ID:          "test-rule-id",
			Title:       "Test Rule",
			Description: "A test rule description",
			Rationale:   "Test rationale",
			Warning:     "Test warning",
			Severity:    "high",
			Instructions: "Test instructions",
			CheckType:   CheckTypePlatform,
			ScannerType: ScannerTypeCEL,
			Expression:  "pods.items.all(p, p.spec.securityContext != null)",
			Inputs: []InputPayload{
				{
					Name: "pods",
					KubernetesInputSpec: KubernetesInputSpec{
						APIVersion:        "v1",
						Resource:          "pods",
						ResourceNamespace: "openshift-compliance",
					},
				},
				{
					Name: "configmaps",
					KubernetesInputSpec: KubernetesInputSpec{
						Group:      "",
						APIVersion: "v1",
						Resource:   "configmaps",
					},
				},
			},
			FailureReason: "Pod(s) without security context found",
		}
	})

	Describe("ToScannerInputs", func() {
		It("converts all named inputs to SDK scanner.Input", func() {
			inputs := payload.ToScannerInputs()
			Expect(inputs).To(HaveLen(2))

			Expect(inputs[0].Name()).To(Equal("pods"))
			Expect(inputs[0].Type()).To(Equal(scanner.InputTypeKubernetes))
			spec0, ok := inputs[0].Spec().(*KubernetesInputSpec)
			Expect(ok).To(BeTrue())
			Expect(spec0.Resource).To(Equal("pods"))
			Expect(spec0.ResourceNamespace).To(Equal("openshift-compliance"))

			Expect(inputs[1].Name()).To(Equal("configmaps"))
			spec1, ok := inputs[1].Spec().(*KubernetesInputSpec)
			Expect(ok).To(BeTrue())
			Expect(spec1.Resource).To(Equal("configmaps"))
		})

		It("skips inputs with empty name", func() {
			payload.Inputs = append(payload.Inputs, InputPayload{
				Name: "",
				KubernetesInputSpec: KubernetesInputSpec{
					APIVersion: "v1",
					Resource:   "secrets",
				},
			})
			inputs := payload.ToScannerInputs()
			Expect(inputs).To(HaveLen(2))
		})

		It("returns empty slice when no inputs", func() {
			payload.Inputs = nil
			inputs := payload.ToScannerInputs()
			Expect(inputs).To(BeEmpty())
		})
	})

	Describe("ToScannerMetadata", func() {
		It("builds metadata with correct name and extensions", func() {
			meta := payload.ToScannerMetadata("my-rule-cr")
			Expect(meta.Name).To(Equal("my-rule-cr"))
			Expect(meta.Description).To(Equal("A test rule description"))
			Expect(meta.Extensions).To(HaveKeyWithValue("id", "test-rule-id"))
			Expect(meta.Extensions).To(HaveKeyWithValue("title", "Test Rule"))
			Expect(meta.Extensions).To(HaveKeyWithValue("severity", "high"))
			Expect(meta.Extensions).To(HaveKeyWithValue("rationale", "Test rationale"))
			Expect(meta.Extensions).To(HaveKeyWithValue("warning", "Test warning"))
			Expect(meta.Extensions).To(HaveKeyWithValue("instructions", "Test instructions"))
			Expect(meta.Extensions).To(HaveKeyWithValue("checkType", CheckTypePlatform))
			Expect(meta.Extensions).To(HaveKey("availableFixes"))
		})

		It("handles empty fields gracefully", func() {
			emptyPayload := RulePayload{ID: "minimal"}
			meta := emptyPayload.ToScannerMetadata("minimal-cr")
			Expect(meta.Name).To(Equal("minimal-cr"))
			Expect(meta.Description).To(BeEmpty())
			Expect(meta.Extensions["title"]).To(Equal(""))
		})
	})
})

var _ = Describe("Rule scanner interfaces", func() {
	var rule *Rule

	BeforeEach(func() {
		rule = &Rule{
			ObjectMeta: metav1.ObjectMeta{Name: "ocp4-cel-security-context"},
			RulePayload: RulePayload{
				ID:          "xccdf_compliance.openshift.io_rule_security-context",
				Title:       "Pods Must Have Security Context",
				Description: "Ensure all pods run as non-root",
				Severity:    "high",
				CheckType:   CheckTypePlatform,
				ScannerType: ScannerTypeCEL,
				Expression:  "pods.items.all(p, p.spec.runAsNonRoot == true)",
				Inputs: []InputPayload{{
					Name: "pods",
					KubernetesInputSpec: KubernetesInputSpec{
						APIVersion:        "v1",
						Resource:          "pods",
						ResourceNamespace: "openshift-compliance",
					},
				}},
				FailureReason: "Non-compliant pods found",
			},
		}
	})

	It("satisfies scanner.Rule interface", func() {
		var _ scanner.Rule = rule
	})

	It("satisfies scanner.CelRule interface", func() {
		var _ scanner.CelRule = rule
	})

	It("returns the CR name as Identifier", func() {
		Expect(rule.Identifier()).To(Equal("ocp4-cel-security-context"))
	})

	It("returns CEL RuleType for CEL rules", func() {
		Expect(rule.Type()).To(Equal(scanner.RuleTypeCEL))
	})

	It("returns Custom RuleType for non-CEL rules", func() {
		rule.RulePayload.ScannerType = ScannerTypeOpenSCAP
		Expect(rule.Type()).To(Equal(scanner.RuleTypeCustom))
	})

	It("returns converted inputs", func() {
		inputs := rule.Inputs()
		Expect(inputs).To(HaveLen(1))
		Expect(inputs[0].Name()).To(Equal("pods"))
	})

	It("returns metadata from shared helper", func() {
		meta := rule.Metadata()
		Expect(meta.Name).To(Equal("ocp4-cel-security-context"))
		Expect(meta.Extensions["id"]).To(Equal("xccdf_compliance.openshift.io_rule_security-context"))
		Expect(meta.Extensions["severity"]).To(Equal("high"))
	})

	It("returns expression as Content", func() {
		Expect(rule.Content()).To(Equal("pods.items.all(p, p.spec.runAsNonRoot == true)"))
	})

	It("returns expression for CEL evaluation", func() {
		Expect(rule.Expression()).To(Equal("pods.items.all(p, p.spec.runAsNonRoot == true)"))
	})

	It("returns failure reason as ErrorMessage", func() {
		Expect(rule.ErrorMessage()).To(Equal("Non-compliant pods found"))
	})
})

var _ = Describe("CustomRule scanner interfaces", func() {
	var cr *CustomRule

	BeforeEach(func() {
		cr = &CustomRule{
			ObjectMeta: metav1.ObjectMeta{Name: "my-custom-rule"},
			Spec: CustomRuleSpec{
				RulePayload: RulePayload{
					ID:          "my-custom-check",
					Title:       "Custom Check",
					Description: "User-created CEL check",
					Severity:    "medium",
					CheckType:   CheckTypePlatform,
					ScannerType: ScannerTypeCEL,
					Expression:  "namespaces.items.size() > 0",
					Inputs: []InputPayload{{
						Name: "namespaces",
						KubernetesInputSpec: KubernetesInputSpec{
							APIVersion: "v1",
							Resource:   "namespaces",
						},
					}},
					FailureReason: "No namespaces found",
				},
			},
		}
	})

	It("satisfies scanner.Rule interface", func() {
		var _ scanner.Rule = cr
	})

	It("satisfies scanner.CelRule interface", func() {
		var _ scanner.CelRule = cr
	})

	It("returns the CR name as Identifier", func() {
		Expect(cr.Identifier()).To(Equal("my-custom-rule"))
	})

	It("returns CEL RuleType", func() {
		Expect(cr.Type()).To(Equal(scanner.RuleTypeCEL))
	})

	It("returns converted inputs via shared helper", func() {
		inputs := cr.Inputs()
		Expect(inputs).To(HaveLen(1))
		Expect(inputs[0].Name()).To(Equal("namespaces"))
	})

	It("returns metadata via shared helper", func() {
		meta := cr.Metadata()
		Expect(meta.Name).To(Equal("my-custom-rule"))
		Expect(meta.Extensions["id"]).To(Equal("my-custom-check"))
		Expect(meta.Extensions["severity"]).To(Equal("medium"))
	})

	It("returns expression as Content", func() {
		Expect(cr.Content()).To(Equal("namespaces.items.size() > 0"))
	})

	It("returns expression for CEL evaluation", func() {
		Expect(cr.Expression()).To(Equal("namespaces.items.size() > 0"))
	})

	It("returns failure reason as ErrorMessage", func() {
		Expect(cr.ErrorMessage()).To(Equal("No namespaces found"))
	})
})

var _ = Describe("Rule and CustomRule produce identical results for same payload", func() {
	var (
		payload RulePayload
		rule    *Rule
		cr      *CustomRule
	)

	BeforeEach(func() {
		payload = RulePayload{
			ID:          "shared-check",
			Title:       "Shared Check",
			Description: "Identical payload",
			Severity:    "low",
			CheckType:   CheckTypePlatform,
			ScannerType: ScannerTypeCEL,
			Expression:  "nodes.items.size() >= 3",
			Inputs: []InputPayload{{
				Name: "nodes",
				KubernetesInputSpec: KubernetesInputSpec{
					APIVersion: "v1",
					Resource:   "nodes",
				},
			}},
			FailureReason: "Not enough nodes",
		}
		rule = &Rule{
			ObjectMeta:  metav1.ObjectMeta{Name: "same-name"},
			RulePayload: payload,
		}
		cr = &CustomRule{
			ObjectMeta: metav1.ObjectMeta{Name: "same-name"},
			Spec:       CustomRuleSpec{RulePayload: payload},
		}
	})

	It("both produce the same Identifier", func() {
		Expect(rule.Identifier()).To(Equal(cr.Identifier()))
	})

	It("both produce the same Type", func() {
		Expect(rule.Type()).To(Equal(cr.Type()))
	})

	It("both produce the same number of Inputs", func() {
		Expect(rule.Inputs()).To(HaveLen(len(cr.Inputs())))
		Expect(rule.Inputs()[0].Name()).To(Equal(cr.Inputs()[0].Name()))
	})

	It("both produce identical Metadata", func() {
		rm := rule.Metadata()
		cm := cr.Metadata()
		Expect(rm.Name).To(Equal(cm.Name))
		Expect(rm.Description).To(Equal(cm.Description))
		Expect(rm.Extensions["id"]).To(Equal(cm.Extensions["id"]))
		Expect(rm.Extensions["severity"]).To(Equal(cm.Extensions["severity"]))
	})

	It("both return the same Content", func() {
		Expect(rule.Content()).To(Equal(cr.Content()))
	})

	It("both return the same Expression", func() {
		Expect(rule.Expression()).To(Equal(cr.Expression()))
	})

	It("both return the same ErrorMessage", func() {
		Expect(rule.ErrorMessage()).To(Equal(cr.ErrorMessage()))
	})
})

var _ = Describe("CustomRule Validate", func() {
	It("passes for valid CEL CustomRule", func() {
		cr := &CustomRule{
			Spec: CustomRuleSpec{
				RulePayload: RulePayload{
					CheckType:   CheckTypePlatform,
					ScannerType: ScannerTypeCEL,
				},
			},
		}
		Expect(cr.Validate()).To(Succeed())
	})

	It("passes when checkType is empty", func() {
		cr := &CustomRule{
			Spec: CustomRuleSpec{
				RulePayload: RulePayload{
					ScannerType: ScannerTypeCEL,
				},
			},
		}
		Expect(cr.Validate()).To(Succeed())
	})

	It("rejects non-Platform checkType", func() {
		cr := &CustomRule{
			Spec: CustomRuleSpec{
				RulePayload: RulePayload{
					CheckType:   CheckTypeNode,
					ScannerType: ScannerTypeCEL,
				},
			},
		}
		Expect(cr.Validate()).To(MatchError(ContainSubstring("checkType must be 'Platform'")))
	})

	It("rejects non-CEL scannerType", func() {
		cr := &CustomRule{
			Spec: CustomRuleSpec{
				RulePayload: RulePayload{
					CheckType:   CheckTypePlatform,
					ScannerType: ScannerTypeOpenSCAP,
				},
			},
		}
		Expect(cr.Validate()).To(MatchError(ContainSubstring("scannerType must be 'CEL'")))
	})
})
