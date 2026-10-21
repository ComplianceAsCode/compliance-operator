package compliancesuite

import (
	"context"
	"encoding/json"

	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/metrics"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/metrics/metricsfakes"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis"
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	mcfgapi "github.com/openshift/api/machineconfiguration"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
)

var _ = Describe("ComplianceSuiteController", func() {
	var (
		suite              *compv1alpha1.ComplianceSuite
		reconciler         *ReconcileComplianceSuite
		logger             logr.Logger
		ctx                = context.Background()
		namespace          = "test-ns"
		suiteName          = "testSuite"
		remediationName    = "testRem"
		targetNodeSelector = map[string]string{
			"hops": "malt",
		}
	)

	suiteAndScansInDonePhase := func() {
		scan1Key := types.NamespacedName{Name: "testScanNode", Namespace: namespace}

		scan1 := &compv1alpha1.ComplianceScan{}

		err := reconciler.Client.Get(ctx, scan1Key, scan1)
		Expect(err).To(BeNil())

		suite.Status.Phase = compv1alpha1.PhaseDone
		scan1Copy := scan1.DeepCopy()
		scan1Copy.Status.Phase = compv1alpha1.PhaseDone

		err = reconciler.Client.Status().Update(ctx, scan1Copy)
		Expect(err).To(BeNil())
		err = reconciler.Client.Status().Update(ctx, suite)
		Expect(err).To(BeNil())
	}

	BeforeEach(func() {
		nodeScanSettings := compv1alpha1.ComplianceScanSpec{
			ScanType:     compv1alpha1.ScanTypeNode,
			NodeSelector: targetNodeSelector,
		}

		suite = &compv1alpha1.ComplianceSuite{
			ObjectMeta: metav1.ObjectMeta{
				Name:            suiteName,
				Namespace:       namespace,
				ResourceVersion: "0",
			},
			Spec: compv1alpha1.ComplianceSuiteSpec{
				Scans: []compv1alpha1.ComplianceScanSpecWrapper{
					{
						Name:               "testScanNode",
						ComplianceScanSpec: nodeScanSettings,
					},
				},
			},
		}
		nodeScan := &compv1alpha1.ComplianceScan{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testScanNode",
				Namespace: namespace,
			},
			Spec: nodeScanSettings,
		}

		cscheme := scheme.Scheme
		err := apis.AddToScheme(cscheme)
		Expect(err).To(BeNil())
		err = mcfgapi.Install(cscheme)
		Expect(err).To(BeNil())

		client := fake.NewClientBuilder().
			WithScheme(cscheme).
			WithStatusSubresource(nodeScan, suite, &compv1alpha1.ComplianceRemediation{}).
			WithRuntimeObjects(nodeScan, suite, &compv1alpha1.ComplianceRemediation{}).
			Build()

		mockMetrics := metrics.NewMetrics(&metricsfakes.FakeImpl{})
		err = mockMetrics.Register()
		Expect(err).To(BeNil())

		reconciler = &ReconcileComplianceSuite{Reader: client, Client: client, Scheme: cscheme, Metrics: mockMetrics}
		zaplog, _ := zap.NewDevelopment()
		logger = zapr.NewLogger(zaplog)
	})

	reconcileAndGetRemediation := func() *compv1alpha1.ComplianceRemediation {
		_, err := reconciler.reconcileRemediations(suite, logger)
		Expect(err).To(BeNil())

		rem := &compv1alpha1.ComplianceRemediation{}
		key := types.NamespacedName{Name: remediationName, Namespace: namespace}
		getErr := reconciler.Client.Get(ctx, key, rem)
		Expect(getErr).To(BeNil())
		return rem
	}

	reconcileShouldNotApplyTheRemediation := func() {
		rem := reconcileAndGetRemediation()
		Expect(rem.Spec.Apply).To(BeFalse())
	}

	prepareOutdatedRemediation := func() {
		rem := &compv1alpha1.ComplianceRemediation{}
		remKey := types.NamespacedName{Name: remediationName, Namespace: namespace}
		err := reconciler.Client.Get(ctx, remKey, rem)
		Expect(err).To(BeNil())
		cm := &corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ConfigMap",
				APIVersion: "v1",
			},
		}
		unstructuredCM, err := runtime.DefaultUnstructuredConverter.ToUnstructured(cm)
		Expect(err).ToNot(HaveOccurred())
		remCopy := rem.DeepCopy()
		remCopy.Spec.Current.Object = &unstructured.Unstructured{
			Object: unstructuredCM,
		}
		err = reconciler.Client.Update(ctx, remCopy)
		Expect(err).To(BeNil())
		remCopyForStatus := remCopy.DeepCopy()
		remCopyForStatus.Status.ApplicationState = compv1alpha1.RemediationOutdated
		err = reconciler.Client.Status().Update(ctx, remCopyForStatus)
		Expect(err).To(BeNil())
	}

	prepareForRemoveOutdatedScenarios := func() {
		prepareOutdatedRemediation()
		if suite.Annotations == nil {
			suite.Annotations = make(map[string]string, 1)
		}
		suite.Annotations[compv1alpha1.RemoveOutdatedAnnotation] = ""
		err := reconciler.Client.Update(ctx, suite)
		Expect(err).To(BeNil())
	}

	shouldRemoveOutdatedRemediation := func() {
		rem := reconcileAndGetRemediation()
		Expect(rem.Spec.Apply).To(BeTrue())
		Expect(rem.Spec.Outdated.Object).To(BeNil())
	}

	Context("When a scan result changes while the phase stays DONE (CMP-4373)", func() {
		scanKey := types.NamespacedName{Name: "testScanNode", Namespace: namespace}

		BeforeEach(func() {
			// The suite has already recorded the scan as DONE/NON-COMPLIANT
			// from a previous cycle.
			suiteCopy := suite.DeepCopy()
			suiteCopy.Status.Phase = compv1alpha1.PhaseDone
			suiteCopy.Status.Result = compv1alpha1.ResultNonCompliant
			suiteCopy.Status.ScanStatuses = []compv1alpha1.ComplianceScanStatusWrapper{
				{
					Name: "testScanNode",
					ComplianceScanStatus: compv1alpha1.ComplianceScanStatus{
						Phase:  compv1alpha1.PhaseDone,
						Result: compv1alpha1.ResultNonCompliant,
					},
				},
			}
			Expect(reconciler.Client.Status().Update(ctx, suiteCopy)).To(BeNil())

			// The scan itself has since flipped to DONE/COMPLIANT (e.g. after a
			// rescan) while staying in the DONE phase.
			scan := &compv1alpha1.ComplianceScan{}
			Expect(reconciler.Client.Get(ctx, scanKey, scan)).To(BeNil())
			scanCopy := scan.DeepCopy()
			scanCopy.Status.Phase = compv1alpha1.PhaseDone
			scanCopy.Status.Result = compv1alpha1.ResultCompliant
			Expect(reconciler.Client.Status().Update(ctx, scanCopy)).To(BeNil())
		})

		It("Should update the suite result even though the phase is unchanged", func() {
			suiteToReconcile := &compv1alpha1.ComplianceSuite{}
			suiteKey := types.NamespacedName{Name: suiteName, Namespace: namespace}
			Expect(reconciler.Client.Get(ctx, suiteKey, suiteToReconcile)).To(BeNil())

			scan := &compv1alpha1.ComplianceScan{}
			Expect(reconciler.Client.Get(ctx, scanKey, scan)).To(BeNil())

			wrap := suiteToReconcile.Status.ScanStatuses[0]
			Expect(reconciler.updateScanStatus(suiteToReconcile, 0, &wrap, scan, logger)).To(BeNil())

			updated := &compv1alpha1.ComplianceSuite{}
			Expect(reconciler.Client.Get(ctx, suiteKey, updated)).To(BeNil())
			Expect(updated.Status.Result).To(Equal(compv1alpha1.ResultCompliant))
			Expect(updated.Status.ScanStatuses[0].Result).To(Equal(compv1alpha1.ResultCompliant))
		})
	})

	Context("When launching a scan for a Profile", func() {
		profileID := "xccdf_org.ssgproject.content_profile_foo"

		BeforeEach(func() {
			// Bundles with the same content have Profiles with the same ID and GUID.
			for _, name := range []string{"bar-foo", "bazz-foo"} {
				Expect(reconciler.Client.Create(ctx, &compv1alpha1.Profile{
					ObjectMeta: metav1.ObjectMeta{
						Name:      name,
						Namespace: namespace,
						Labels:    map[string]string{compv1alpha1.ProfileGuidLabel: "foo-guid"},
					},
					ProfilePayload: compv1alpha1.ProfilePayload{ID: profileID},
				})).To(Succeed())
			}
		})

		launchAndGetScan := func(scanName, role string) *compv1alpha1.ComplianceScan {
			scanWrap := &compv1alpha1.ComplianceScanSpecWrapper{
				Name: scanName,
				ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
					ScanType:     compv1alpha1.ScanTypeNode,
					Profile:      profileID,
					NodeSelector: utils.GetNodeRoleSelector(role),
				},
			}
			Expect(launchScanForSuite(reconciler, suite, scanWrap, logger)).To(Succeed())
			scan := &compv1alpha1.ComplianceScan{}
			Expect(reconciler.Client.Get(ctx, types.NamespacedName{Name: scanName, Namespace: namespace}, scan)).To(Succeed())
			return scan
		}

		It("Should label the scan with the name of the Profile it is for", func() {
			scan := launchAndGetScan("bazz-foo-worker", "worker")
			Expect(scan.Labels).To(HaveKeyWithValue(compv1alpha1.ProfileNameLabel, "bazz-foo"))
			Expect(scan.Labels).To(HaveKeyWithValue(compv1alpha1.ProfileGuidLabel, "foo-guid"))
		})

		It("Should label a scan for the @all role with the name of the Profile it is for", func() {
			// A ScanSettingBinding names the scans of the @all role
			// <profile>-a-all, and gives them no role in their node selector.
			scan := launchAndGetScan("bazz-foo-a-all", compv1alpha1.AllRoles)
			Expect(scan.Labels).To(HaveKeyWithValue(compv1alpha1.ProfileNameLabel, "bazz-foo"))
			Expect(scan.Labels).To(HaveKeyWithValue(compv1alpha1.ProfileGuidLabel, "foo-guid"))
		})

		It("Should not label a scan whose name doesn't come from a Profile", func() {
			scan := launchAndGetScan("my-scan", "worker")
			Expect(scan.Labels).NotTo(HaveKey(compv1alpha1.ProfileNameLabel))
		})
	})

	Context("When reconciling the labels of an existing scan", func() {
		profileID := "xccdf_org.ssgproject.content_profile_foo"

		BeforeEach(func() {
			// Bundles with the same content have Profiles with the same ID and GUID.
			for _, name := range []string{"bar-foo", "bazz-foo"} {
				Expect(reconciler.Client.Create(ctx, &compv1alpha1.Profile{
					ObjectMeta: metav1.ObjectMeta{
						Name:      name,
						Namespace: namespace,
						Labels:    map[string]string{compv1alpha1.ProfileGuidLabel: "foo-guid"},
					},
					ProfilePayload: compv1alpha1.ProfilePayload{ID: profileID},
				})).To(Succeed())
			}
		})

		// existingScan creates a scan with the given labels, as an older
		// operator would have created it.
		existingScan := func(scanName, role string, scanLabels map[string]string) *compv1alpha1.ComplianceScanSpecWrapper {
			scanWrap := &compv1alpha1.ComplianceScanSpecWrapper{
				Name: scanName,
				ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
					ScanType:     compv1alpha1.ScanTypeNode,
					Profile:      profileID,
					NodeSelector: utils.GetNodeRoleSelector(role),
				},
			}
			scan := compv1alpha1.ComplianceScanFromWrapper(scanWrap)
			scan.SetNamespace(namespace)
			scan.SetLabels(scanLabels)
			Expect(reconciler.Client.Create(ctx, scan)).To(Succeed())
			return scanWrap
		}

		getScan := func(name string) *compv1alpha1.ComplianceScan {
			scan := &compv1alpha1.ComplianceScan{}
			Expect(reconciler.Client.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, scan)).To(Succeed())
			return scan
		}

		reconcileAndGetScan := func(scanWrap *compv1alpha1.ComplianceScanSpecWrapper) *compv1alpha1.ComplianceScan {
			Expect(reconciler.reconcileScanLabels(suite, scanWrap, getScan(scanWrap.Name), logger)).To(Succeed())
			return getScan(scanWrap.Name)
		}

		It("Should add the Profile name to a scan created without it", func() {
			scanWrap := existingScan("bazz-foo-worker", "worker", map[string]string{
				compv1alpha1.SuiteLabel:       suiteName,
				compv1alpha1.ProfileGuidLabel: "foo-guid",
			})
			scan := reconcileAndGetScan(scanWrap)
			Expect(scan.Labels).To(HaveKeyWithValue(compv1alpha1.ProfileNameLabel, "bazz-foo"))
			Expect(scan.Labels).To(HaveKeyWithValue(compv1alpha1.ProfileGuidLabel, "foo-guid"))
			Expect(scan.Labels).To(HaveKeyWithValue(compv1alpha1.SuiteLabel, suiteName))
		})

		It("Should add both Profile labels to an existing scan of the @all role", func() {
			scanWrap := existingScan("bazz-foo-a-all", compv1alpha1.AllRoles, map[string]string{
				compv1alpha1.SuiteLabel:       suiteName,
				compv1alpha1.ProfileGuidLabel: "",
			})
			scan := reconcileAndGetScan(scanWrap)
			Expect(scan.Labels).To(HaveKeyWithValue(compv1alpha1.ProfileNameLabel, "bazz-foo"))
			Expect(scan.Labels).To(HaveKeyWithValue(compv1alpha1.ProfileGuidLabel, "foo-guid"))
		})

		It("Should keep the Profile labels a scan already has", func() {
			scanWrap := existingScan("bazz-foo-worker", "worker", map[string]string{
				compv1alpha1.SuiteLabel:       suiteName,
				compv1alpha1.ProfileGuidLabel: "other-guid",
				compv1alpha1.ProfileNameLabel: "bar-foo",
			})
			before := getScan(scanWrap.Name)
			scan := reconcileAndGetScan(scanWrap)
			Expect(scan.Labels).To(Equal(before.Labels))
			Expect(scan.ResourceVersion).To(Equal(before.ResourceVersion))
		})

		It("Should keep the GUID a scan has while adding its Profile name", func() {
			scanWrap := existingScan("bazz-foo-worker", "worker", map[string]string{
				compv1alpha1.SuiteLabel:       suiteName,
				compv1alpha1.ProfileGuidLabel: "other-guid",
			})
			scan := reconcileAndGetScan(scanWrap)
			Expect(scan.Labels).To(HaveKeyWithValue(compv1alpha1.ProfileGuidLabel, "other-guid"))
			Expect(scan.Labels).To(HaveKeyWithValue(compv1alpha1.ProfileNameLabel, "bazz-foo"))
		})

		It("Should keep the Profile name a scan has while adding its GUID", func() {
			scanWrap := existingScan("bazz-foo-worker", "worker", map[string]string{
				compv1alpha1.SuiteLabel:       suiteName,
				compv1alpha1.ProfileGuidLabel: "",
				compv1alpha1.ProfileNameLabel: "bar-foo",
			})
			scan := reconcileAndGetScan(scanWrap)
			Expect(scan.Labels).To(HaveKeyWithValue(compv1alpha1.ProfileNameLabel, "bar-foo"))
			Expect(scan.Labels).To(HaveKeyWithValue(compv1alpha1.ProfileGuidLabel, "foo-guid"))
		})

		It("Should leave a scan that isn't named after a Profile alone", func() {
			scanWrap := existingScan("my-scan", "worker", map[string]string{
				compv1alpha1.SuiteLabel:       suiteName,
				compv1alpha1.ProfileGuidLabel: "",
			})
			before := getScan(scanWrap.Name)
			scan := reconcileAndGetScan(scanWrap)
			Expect(scan.Labels).NotTo(HaveKey(compv1alpha1.ProfileNameLabel))
			Expect(scan.ResourceVersion).To(Equal(before.ResourceVersion))
		})

		It("Should add the labels when the suite reconciles its scans", func() {
			scanWrap := existingScan("bazz-foo-worker", "worker", map[string]string{
				compv1alpha1.SuiteLabel:       suiteName,
				compv1alpha1.ProfileGuidLabel: "foo-guid",
			})
			suite.Spec.Scans = []compv1alpha1.ComplianceScanSpecWrapper{*scanWrap}
			_, err := reconciler.reconcileScans(suite, logger)
			Expect(err).To(BeNil())
			Expect(getScan(scanWrap.Name).Labels).To(HaveKeyWithValue(compv1alpha1.ProfileNameLabel, "bazz-foo"))
		})
	})

	Context("When reconciling generic remediations", func() {
		BeforeEach(func() {
			remediation := &compv1alpha1.ComplianceRemediation{
				ObjectMeta: metav1.ObjectMeta{
					Name:      remediationName,
					Namespace: namespace,
					Labels: map[string]string{
						compv1alpha1.SuiteLabel:          suiteName,
						compv1alpha1.ComplianceScanLabel: "testScanNode",
					},
				},
				Spec: compv1alpha1.ComplianceRemediationSpec{
					ComplianceRemediationSpecMeta: compv1alpha1.ComplianceRemediationSpecMeta{
						Apply: false,
					},
					Current: compv1alpha1.ComplianceRemediationPayload{
						Object: nil,
					},
				},
			}
			cm := &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
			}
			unstructuredCM, err := runtime.DefaultUnstructuredConverter.ToUnstructured(cm)
			Expect(err).ToNot(HaveOccurred())
			remediation.Spec.Current.Object = &unstructured.Unstructured{
				Object: unstructuredCM,
			}
			err = reconciler.Client.Create(ctx, remediation.DeepCopy())
			Expect(err).To(BeNil())
		})

		reconcileShouldApplyTheRemediation := func() {
			By("Running a reconcile loop")
			rem := reconcileAndGetRemediation()
			Expect(rem.Spec.Apply).To(BeTrue())

			By("The remediation controller setting the applied status")
			rem.Status.ApplicationState = compv1alpha1.RemediationApplied
			err := reconciler.Client.Status().Update(ctx, rem)
			Expect(err).To(BeNil())

			By("Running a second reconcile loop")
			_, err = reconciler.reconcileRemediations(suite, logger)
			Expect(err).To(BeNil())
		}

		Context("With spec.AutoApplyRemediations = false", func() {
			It("Should leave the remediation unapplied", reconcileShouldNotApplyTheRemediation)
		})

		Context("With spec.AutoApplyRemediations = true", func() {
			BeforeEach(func() {
				suite.Spec.AutoApplyRemediations = true
				err := reconciler.Client.Update(ctx, suite)
				Expect(err).To(BeNil())
			})
			Context("With ComplianceSuite and Scans not done", func() {
				It("Should not apply the remediation", reconcileShouldNotApplyTheRemediation)
			})
			Context("With ComplianceSuite and Scans DONE", func() {
				BeforeEach(suiteAndScansInDonePhase)
				It("Should apply the remediation", reconcileShouldApplyTheRemediation)

				Context("With remove-outdated annotation", func() {
					BeforeEach(prepareForRemoveOutdatedScenarios)
					It("Should remove the outdated remediation and remove the annotation", func() {
						By("Reconciling the remediations")
						shouldRemoveOutdatedRemediation()

						By("Verifying the suite no longer has the remove-outdated annotation")
						key := types.NamespacedName{Name: suiteName, Namespace: namespace}
						s := &compv1alpha1.ComplianceSuite{}
						err := reconciler.Client.Get(ctx, key, s)
						Expect(err).To(BeNil())
						Expect(s.Annotations).ToNot(HaveKey(compv1alpha1.RemoveOutdatedAnnotation))
					})
				})
			})
		})

		Context("With apply-remediations annotation", func() {
			BeforeEach(func() {
				suite.Annotations = make(map[string]string, 2)
				suite.Annotations[compv1alpha1.ApplyRemediationsAnnotation] = ""
				err := reconciler.Client.Update(ctx, suite)
				Expect(err).To(BeNil())
			})
			Context("With ComplianceSuite and Scans not done", func() {
				It("Should not apply the remediation", reconcileShouldNotApplyTheRemediation)
			})
			Context("With ComplianceSuite and Scans DONE", func() {
				BeforeEach(suiteAndScansInDonePhase)
				It("Should apply the remediation and remove the annotation", func() {
					By("Reconciling the remediations")
					reconcileShouldApplyTheRemediation()

					By("Verifying the suite no longer has the apply-remediation annotation")
					key := types.NamespacedName{Name: suiteName, Namespace: namespace}
					s := &compv1alpha1.ComplianceSuite{}
					err := reconciler.Client.Get(ctx, key, s)
					Expect(err).To(BeNil())
					Expect(s.Annotations).ToNot(HaveKey(compv1alpha1.ApplyRemediationsAnnotation))
				})

				Context("With remove-outdated annotation", func() {
					BeforeEach(prepareForRemoveOutdatedScenarios)
					It("Should remove the outdated remediation and remove the annotation", func() {
						By("Reconciling the remediations")
						shouldRemoveOutdatedRemediation()

						By("Verifying the suite no longer has the remove-outdated annotation")
						key := types.NamespacedName{Name: suiteName, Namespace: namespace}
						s := &compv1alpha1.ComplianceSuite{}
						err := reconciler.Client.Get(ctx, key, s)
						Expect(err).To(BeNil())
						Expect(s.Annotations).ToNot(HaveKey(compv1alpha1.RemoveOutdatedAnnotation))
					})
				})
			})
		})
	})

	Context("When reconciling MachineConfig remediations", func() {
		var poolName = "test-pool"
		BeforeEach(func() {
			mcp := &mcfgv1.MachineConfigPool{
				TypeMeta: metav1.TypeMeta{
					Kind:       "MachineConfigPool",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: poolName,
				},
				Spec: mcfgv1.MachineConfigPoolSpec{
					NodeSelector: &metav1.LabelSelector{
						MatchLabels: targetNodeSelector,
					},
				},
			}
			err := reconciler.Client.Create(ctx, mcp)
			Expect(err).To(BeNil())

			remediation := &compv1alpha1.ComplianceRemediation{
				ObjectMeta: metav1.ObjectMeta{
					Name:      remediationName,
					Namespace: namespace,
					Labels: map[string]string{
						compv1alpha1.SuiteLabel:          suiteName,
						compv1alpha1.ComplianceScanLabel: "testScanNode",
					},
				},
				Spec: compv1alpha1.ComplianceRemediationSpec{
					ComplianceRemediationSpecMeta: compv1alpha1.ComplianceRemediationSpecMeta{
						Apply: false,
					},
					Current: compv1alpha1.ComplianceRemediationPayload{
						Object: nil,
					},
				},
			}
			mc := &mcfgv1.MachineConfig{
				TypeMeta: metav1.TypeMeta{
					Kind:       "MachineConfig",
					APIVersion: mcfgapi.GroupName + "/v1",
				},
			}
			unstructuredMC, err := runtime.DefaultUnstructuredConverter.ToUnstructured(mc)
			Expect(err).ToNot(HaveOccurred())
			remediation.Spec.Current.Object = &unstructured.Unstructured{
				Object: unstructuredMC,
			}
			err = reconciler.Client.Create(ctx, remediation.DeepCopy())
			Expect(err).To(BeNil())
		})

		reconcileShouldApplyTheRemediationAndHandlePausingPools := func() {
			By("Running a reconcile loop")
			rem := reconcileAndGetRemediation()
			Expect(rem.Spec.Apply).To(BeTrue())

			By("The remediation controller setting the applied status")
			rem.Status.ApplicationState = compv1alpha1.RemediationApplied
			err := reconciler.Client.Status().Update(ctx, rem)
			Expect(err).To(BeNil())

			By("the pool should be paused")
			p := &mcfgv1.MachineConfigPool{}
			poolkey := types.NamespacedName{Name: poolName}
			err = reconciler.Client.Get(ctx, poolkey, p)
			Expect(err).To(BeNil())
			Expect(p.Spec.Paused).To(BeTrue())

			By("Running a second reconcile loop")
			_, err = reconciler.reconcileRemediations(suite, logger)
			Expect(err).To(BeNil())

			By("the pool should be un-paused")
			err = reconciler.Client.Get(ctx, poolkey, p)
			Expect(err).To(BeNil())
			Expect(p.Spec.Paused).To(BeFalse())
		}

		Context("With spec.AutoApplyRemediations = true", func() {
			BeforeEach(func() {
				suite.Spec.AutoApplyRemediations = true
				err := reconciler.Client.Update(ctx, suite)
				Expect(err).To(BeNil())
			})
			Context("With ComplianceSuite and Scans not done", func() {
				It("Should not apply the remediation", reconcileShouldNotApplyTheRemediation)
			})
			Context("With ComplianceSuite and Scans DONE", func() {
				BeforeEach(suiteAndScansInDonePhase)
				It("Should apply the remediation", reconcileShouldApplyTheRemediationAndHandlePausingPools)

				Context("With remove-outdated annotation", func() {
					BeforeEach(prepareForRemoveOutdatedScenarios)
					It("Should remove the outdated remediation and remove the annotation", func() {
						By("Reconciling the remediations")
						shouldRemoveOutdatedRemediation()

						By("Verifying the suite no longer has the remove-outdated annotation")
						key := types.NamespacedName{Name: suiteName, Namespace: namespace}
						s := &compv1alpha1.ComplianceSuite{}
						err := reconciler.Client.Get(ctx, key, s)
						Expect(err).To(BeNil())
						Expect(s.Annotations).ToNot(HaveKey(compv1alpha1.RemoveOutdatedAnnotation))
					})
				})
			})
		})

		Context("With apply-remediations annotation", func() {
			BeforeEach(func() {
				suite.Annotations = make(map[string]string, 2)
				suite.Annotations[compv1alpha1.ApplyRemediationsAnnotation] = ""
				err := reconciler.Client.Update(ctx, suite)
				Expect(err).To(BeNil())
			})
			Context("With ComplianceSuite and Scans not done", func() {
				It("Should not apply the remediation", reconcileShouldNotApplyTheRemediation)
			})
			Context("With ComplianceSuite and Scans DONE", func() {
				BeforeEach(suiteAndScansInDonePhase)
				It("Should apply the remediation and remove the annotation", func() {
					By("Reconciling the remediations")
					reconcileShouldApplyTheRemediationAndHandlePausingPools()

					By("Verifying the suite no longer has the apply-remediation annotation")
					key := types.NamespacedName{Name: suiteName, Namespace: namespace}
					s := &compv1alpha1.ComplianceSuite{}
					err := reconciler.Client.Get(ctx, key, s)
					Expect(err).To(BeNil())
					Expect(s.Annotations).ToNot(HaveKey(compv1alpha1.ApplyRemediationsAnnotation))
				})

				Context("With remove-outdated annotation", func() {
					BeforeEach(prepareForRemoveOutdatedScenarios)
					It("Should remove the outdated remediation and remove the annotation", func() {
						By("Reconciling the remediations")
						shouldRemoveOutdatedRemediation()

						By("Verifying the suite no longer has the remove-outdated annotation")
						key := types.NamespacedName{Name: suiteName, Namespace: namespace}
						s := &compv1alpha1.ComplianceSuite{}
						err := reconciler.Client.Get(ctx, key, s)
						Expect(err).To(BeNil())
						Expect(s.Annotations).ToNot(HaveKey(compv1alpha1.RemoveOutdatedAnnotation))
					})
				})
			})
		})
	})
	// testing for KC remediation

	Context("When reconciling KubeletConfig remediations", func() {
		var poolName = "test-pool"
		remediationKCPayload := `
			{
				"something": "0s"
			}
			`
		BeforeEach(func() {
			mcp := &mcfgv1.MachineConfigPool{
				TypeMeta: metav1.TypeMeta{
					Kind:       "MachineConfigPool",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: poolName,
				},
				Spec: mcfgv1.MachineConfigPoolSpec{
					NodeSelector: &metav1.LabelSelector{
						MatchLabels: targetNodeSelector,
					},
					Configuration: mcfgv1.MachineConfigPoolStatusConfiguration{
						Source: []corev1.ObjectReference{{Name: "99-master-generated-kubelet"}},
					},
				},
			}
			err := reconciler.Client.Create(ctx, mcp)
			Expect(err).To(BeNil())

			remediation := &compv1alpha1.ComplianceRemediation{
				ObjectMeta: metav1.ObjectMeta{
					Name:      remediationName,
					Namespace: namespace,
					Labels: map[string]string{
						compv1alpha1.SuiteLabel:          suiteName,
						compv1alpha1.ComplianceScanLabel: "testScanNode",
					},
				},
				Spec: compv1alpha1.ComplianceRemediationSpec{
					ComplianceRemediationSpecMeta: compv1alpha1.ComplianceRemediationSpecMeta{
						Apply: false,
					},
					Current: compv1alpha1.ComplianceRemediationPayload{
						Object: nil,
					},
				},
			}
			kcPayload := `{"apiVersion": "machineconfiguration.openshift.io/v1","kind": "KubeletConfig","spec": {"kubeletConfig": {"streamingConnectionIdleTimeout": "0s"}}}`

			renderdKC := `{"ignition":{"version":"3.2.0"}}`
			//prepare machine config for testing
			kcOwnerRef := metav1.OwnerReference{
				APIVersion: "machineconfiguration.openshift.io/v1",
				Kind:       "KubeletConfig",
				Name:       "kubelet-config-compliance-operator",
				UID:        "12345",
			}

			mc := &mcfgv1.MachineConfig{
				TypeMeta: metav1.TypeMeta{
					Kind:       "MachineConfig",
					APIVersion: "machineconfiguration.openshift.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{kcOwnerRef},
					Name:            "99-master-generated-kubelet",
				},
				Spec: mcfgv1.MachineConfigSpec{
					Config: runtime.RawExtension{
						Raw: []byte(renderdKC),
					},
				},
			}
			err = reconciler.Client.Create(ctx, mc)
			Expect(err).To(BeNil())

			existingKCPayload := `{}`
			existingKCObj := &mcfgv1.KubeletConfig{
				TypeMeta: metav1.TypeMeta{
					Kind:       "KubeletConfig",
					APIVersion: "machineconfiguration.openshift.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "kubelet-config-compliance-operator",
				},
				Spec: mcfgv1.KubeletConfigSpec{
					KubeletConfig: &runtime.RawExtension{
						Raw: []byte(existingKCPayload),
					},
				},
			}
			//create existing kubelet config
			err = reconciler.Client.Create(ctx, existingKCObj.DeepCopy())
			Expect(err).To(BeNil())

			var obj map[string]interface{}
			err = json.Unmarshal([]byte(kcPayload), &obj)
			Expect(err).ToNot(HaveOccurred())
			remediation.Spec.Current.Object = &unstructured.Unstructured{
				Object: obj,
			}
			err = reconciler.Client.Create(ctx, remediation.DeepCopy())
			Expect(err).To(BeNil())

		})

		reconcileShouldApplyTheRemediationAndHandlePausingPools := func() {
			By("Running a reconcile loop")
			rem := reconcileAndGetRemediation()
			Expect(rem.Spec.Apply).To(BeTrue())

			By("The remediation controller setting the applied status")
			rem.Status.ApplicationState = compv1alpha1.RemediationApplied
			err := reconciler.Client.Status().Update(ctx, rem)
			Expect(err).To(BeNil())

			By("the pool should be paused")
			p := &mcfgv1.MachineConfigPool{}
			poolkey := types.NamespacedName{Name: poolName}
			err = reconciler.Client.Get(ctx, poolkey, p)
			Expect(err).To(BeNil())
			Expect(p.Spec.Paused).To(BeTrue())

			By("The remediation controller should create/patch the kubelet config object")
			kc := &mcfgv1.KubeletConfig{}
			kckey := types.NamespacedName{Name: "kubelet-config-compliance-operator"}
			err = reconciler.Client.Get(ctx, kckey, kc)
			Expect(err).To(BeNil())
			kc.Spec.KubeletConfig.Raw = []byte(remediationKCPayload)
			err = reconciler.Client.Patch(ctx, kc, client.Merge)
			Expect(err).To(BeNil())

			By("Running a second reconcile loop")
			_, err = reconciler.reconcileRemediations(suite, logger)
			Expect(err).To(BeNil())

			By("the pool should be un-paused")
			err = reconciler.Client.Get(ctx, poolkey, p)
			Expect(err).To(BeNil())
			Expect(p.Spec.Paused).To(BeFalse())

			s := &compv1alpha1.ComplianceRemediation{}
			key := types.NamespacedName{Name: remediationName, Namespace: namespace}
			reconciler.Client.Get(ctx, key, s)

		}

		Context("With spec.AutoApplyRemediations = true", func() {
			BeforeEach(func() {
				suite.Spec.AutoApplyRemediations = true
				err := reconciler.Client.Update(ctx, suite)
				Expect(err).To(BeNil())
			})
			Context("With ComplianceSuite and Scans not done", func() {
				It("Should not apply the remediation", reconcileShouldNotApplyTheRemediation)
			})
			Context("With ComplianceSuite and Scans DONE", func() {
				BeforeEach(suiteAndScansInDonePhase)
				It("Should apply the remediation", reconcileShouldApplyTheRemediationAndHandlePausingPools)

				Context("With remove-outdated annotation", func() {
					BeforeEach(prepareForRemoveOutdatedScenarios)
					It("Should remove the outdated remediation and remove the annotation", func() {
						By("Reconciling the remediations")
						shouldRemoveOutdatedRemediation()

						By("Verifying the suite no longer has the remove-outdated annotation")
						key := types.NamespacedName{Name: suiteName, Namespace: namespace}
						s := &compv1alpha1.ComplianceSuite{}
						err := reconciler.Client.Get(ctx, key, s)
						Expect(err).To(BeNil())
						Expect(s.Annotations).ToNot(HaveKey(compv1alpha1.RemoveOutdatedAnnotation))
					})
				})
			})
		})

		Context("With apply-remediations annotation", func() {
			BeforeEach(func() {
				suite.Annotations = make(map[string]string, 2)
				suite.Annotations[compv1alpha1.ApplyRemediationsAnnotation] = ""
				err := reconciler.Client.Update(ctx, suite)
				Expect(err).To(BeNil())
			})
			Context("With ComplianceSuite and Scans not done", func() {
				It("Should not apply the remediation", reconcileShouldNotApplyTheRemediation)
			})
			Context("With ComplianceSuite and Scans DONE", func() {
				BeforeEach(suiteAndScansInDonePhase)
				It("Should apply the remediation and remove the annotation", func() {
					By("Reconciling the remediations")
					reconcileShouldApplyTheRemediationAndHandlePausingPools()

					By("Verifying the suite no longer has the apply-remediation annotation")
					key := types.NamespacedName{Name: suiteName, Namespace: namespace}
					s := &compv1alpha1.ComplianceSuite{}
					err := reconciler.Client.Get(ctx, key, s)
					Expect(err).To(BeNil())
					Expect(s.Annotations).ToNot(HaveKey(compv1alpha1.ApplyRemediationsAnnotation))
				})

				Context("With remove-outdated annotation", func() {
					BeforeEach(prepareForRemoveOutdatedScenarios)
					It("Should remove the outdated remediation and remove the annotation", func() {
						By("Reconciling the remediations")
						shouldRemoveOutdatedRemediation()

						By("Verifying the suite no longer has the remove-outdated annotation")
						key := types.NamespacedName{Name: suiteName, Namespace: namespace}
						s := &compv1alpha1.ComplianceSuite{}
						err := reconciler.Client.Get(ctx, key, s)
						Expect(err).To(BeNil())
						Expect(s.Annotations).ToNot(HaveKey(compv1alpha1.RemoveOutdatedAnnotation))
					})
				})
			})
		})
	})

	// testing for KC remediation Base64 encoding
	// OVN cluster has base64 encoding

	Context("When reconciling KubeletConfig remediations", func() {
		var poolName = "test-pool-base64"
		remediationKCPayload := `
				{
					"something": "0s"
				}
				`

		BeforeEach(func() {
			mcp := &mcfgv1.MachineConfigPool{
				TypeMeta: metav1.TypeMeta{
					Kind:       "MachineConfigPool",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: poolName,
				},
				Spec: mcfgv1.MachineConfigPoolSpec{
					NodeSelector: &metav1.LabelSelector{
						MatchLabels: targetNodeSelector,
					},
					Configuration: mcfgv1.MachineConfigPoolStatusConfiguration{
						Source: []corev1.ObjectReference{{Name: "99-master-generated-kubelet"}},
					},
				},
			}
			err := reconciler.Client.Create(ctx, mcp)
			Expect(err).To(BeNil())

			remediation := &compv1alpha1.ComplianceRemediation{
				ObjectMeta: metav1.ObjectMeta{
					Name:      remediationName,
					Namespace: namespace,
					Labels: map[string]string{
						compv1alpha1.SuiteLabel:          suiteName,
						compv1alpha1.ComplianceScanLabel: "testScanNode",
					},
				},
				Spec: compv1alpha1.ComplianceRemediationSpec{
					ComplianceRemediationSpecMeta: compv1alpha1.ComplianceRemediationSpecMeta{
						Apply: false,
					},
					Current: compv1alpha1.ComplianceRemediationPayload{
						Object: nil,
					},
				},
			}
			kcPayload := `{"apiVersion": "machineconfiguration.openshift.io/v1","kind": "KubeletConfig","spec": {"kubeletConfig": {"streamingConnectionIdleTimeout": "0s"}}}`

			renderdKC := `{"ignition":{"version":"3.2.0"}}`
			//prepare machine config for testing
			kcOwnerRef := metav1.OwnerReference{
				APIVersion: "machineconfiguration.openshift.io/v1",
				Kind:       "KubeletConfig",
				Name:       "kubelet-config-compliance-operator",
				UID:        "12345",
			}

			mc := &mcfgv1.MachineConfig{
				TypeMeta: metav1.TypeMeta{
					Kind:       "MachineConfig",
					APIVersion: "machineconfiguration.openshift.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{kcOwnerRef},
					Name:            "99-master-generated-kubelet",
				},
				Spec: mcfgv1.MachineConfigSpec{
					Config: runtime.RawExtension{
						Raw: []byte(renderdKC),
					},
				},
			}
			err = reconciler.Client.Create(ctx, mc)
			Expect(err).To(BeNil())

			existingKCPayload := `{}`
			existingKCObj := &mcfgv1.KubeletConfig{
				TypeMeta: metav1.TypeMeta{
					Kind:       "KubeletConfig",
					APIVersion: "machineconfiguration.openshift.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "kubelet-config-compliance-operator",
				},
				Spec: mcfgv1.KubeletConfigSpec{
					KubeletConfig: &runtime.RawExtension{
						Raw: []byte(existingKCPayload),
					},
				},
			}
			//create existing kubelet config
			err = reconciler.Client.Create(ctx, existingKCObj.DeepCopy())
			Expect(err).To(BeNil())

			var obj map[string]interface{}
			err = json.Unmarshal([]byte(kcPayload), &obj)
			Expect(err).ToNot(HaveOccurred())
			remediation.Spec.Current.Object = &unstructured.Unstructured{
				Object: obj,
			}
			err = reconciler.Client.Create(ctx, remediation.DeepCopy())
			Expect(err).To(BeNil())

		})

		reconcileShouldApplyTheRemediationAndHandlePausingPools := func() {
			By("Running a reconcile loop")
			rem := reconcileAndGetRemediation()
			Expect(rem.Spec.Apply).To(BeTrue())

			By("The remediation controller setting the applied status")
			rem.Status.ApplicationState = compv1alpha1.RemediationApplied
			err := reconciler.Client.Status().Update(ctx, rem)
			Expect(err).To(BeNil())

			By("the pool should be paused")
			p := &mcfgv1.MachineConfigPool{}
			poolkey := types.NamespacedName{Name: poolName}
			err = reconciler.Client.Get(ctx, poolkey, p)
			Expect(err).To(BeNil())
			Expect(p.Spec.Paused).To(BeTrue())

			By("The remediation controller should create/patch the kubelet config object")
			kc := &mcfgv1.KubeletConfig{}
			kckey := types.NamespacedName{Name: "kubelet-config-compliance-operator"}
			err = reconciler.Client.Get(ctx, kckey, kc)
			Expect(err).To(BeNil())
			kc.Spec.KubeletConfig.Raw = []byte(remediationKCPayload)
			err = reconciler.Client.Patch(ctx, kc, client.Merge)
			Expect(err).To(BeNil())

			By("Running a second reconcile loop")
			_, err = reconciler.reconcileRemediations(suite, logger)
			Expect(err).To(BeNil())

			By("the pool should be un-paused")
			err = reconciler.Client.Get(ctx, poolkey, p)
			Expect(err).To(BeNil())
			Expect(p.Spec.Paused).To(BeFalse())
			s := &compv1alpha1.ComplianceRemediation{}
			key := types.NamespacedName{Name: remediationName, Namespace: namespace}
			reconciler.Client.Get(ctx, key, s)

		}

		Context("With spec.AutoApplyRemediations = true", func() {
			BeforeEach(func() {
				suite.Spec.AutoApplyRemediations = true
				err := reconciler.Client.Update(ctx, suite)
				Expect(err).To(BeNil())
			})
			Context("With ComplianceSuite and Scans not done", func() {
				It("Should not apply the remediation", reconcileShouldNotApplyTheRemediation)
			})
			Context("With ComplianceSuite and Scans DONE", func() {
				BeforeEach(suiteAndScansInDonePhase)
				It("Should apply the remediation", reconcileShouldApplyTheRemediationAndHandlePausingPools)

				Context("With remove-outdated annotation", func() {
					BeforeEach(prepareForRemoveOutdatedScenarios)
					It("Should remove the outdated remediation and remove the annotation", func() {
						By("Reconciling the remediations")
						shouldRemoveOutdatedRemediation()

						By("Verifying the suite no longer has the remove-outdated annotation")
						key := types.NamespacedName{Name: suiteName, Namespace: namespace}
						s := &compv1alpha1.ComplianceSuite{}
						err := reconciler.Client.Get(ctx, key, s)
						Expect(err).To(BeNil())
						Expect(s.Annotations).ToNot(HaveKey(compv1alpha1.RemoveOutdatedAnnotation))
					})
				})
			})
		})

		Context("With apply-remediations annotation", func() {
			BeforeEach(func() {
				suite.Annotations = make(map[string]string, 2)
				suite.Annotations[compv1alpha1.ApplyRemediationsAnnotation] = ""
				err := reconciler.Client.Update(ctx, suite)
				Expect(err).To(BeNil())
			})
			Context("With ComplianceSuite and Scans not done", func() {
				It("Should not apply the remediation", reconcileShouldNotApplyTheRemediation)
			})
			Context("With ComplianceSuite and Scans DONE", func() {
				BeforeEach(suiteAndScansInDonePhase)
				It("Should apply the remediation and remove the annotation", func() {
					By("Reconciling the remediations")
					reconcileShouldApplyTheRemediationAndHandlePausingPools()

					By("Verifying the suite no longer has the apply-remediation annotation")
					key := types.NamespacedName{Name: suiteName, Namespace: namespace}
					s := &compv1alpha1.ComplianceSuite{}
					err := reconciler.Client.Get(ctx, key, s)
					Expect(err).To(BeNil())
					Expect(s.Annotations).ToNot(HaveKey(compv1alpha1.ApplyRemediationsAnnotation))
				})

				Context("With remove-outdated annotation", func() {
					BeforeEach(prepareForRemoveOutdatedScenarios)
					It("Should remove the outdated remediation and remove the annotation", func() {
						By("Reconciling the remediations")
						shouldRemoveOutdatedRemediation()

						By("Verifying the suite no longer has the remove-outdated annotation")
						key := types.NamespacedName{Name: suiteName, Namespace: namespace}
						s := &compv1alpha1.ComplianceSuite{}
						err := reconciler.Client.Get(ctx, key, s)
						Expect(err).To(BeNil())
						Expect(s.Annotations).ToNot(HaveKey(compv1alpha1.RemoveOutdatedAnnotation))
					})
				})
			})
		})
	})

})
