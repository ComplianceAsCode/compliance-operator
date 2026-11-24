package remediation_e2e

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"testing"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	configv1 "github.com/openshift/api/config/v1"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var brokenContentImagePath string
var contentImagePath string

func TestMain(m *testing.M) {
	f := framework.NewFramework(framework.WithTestPools())
	err := f.SetUp()
	if err != nil {
		log.Fatal(err)
	}

	contentImagePath = os.Getenv("CONTENT_IMAGE")
	if contentImagePath == "" {
		fmt.Println("Please set the 'CONTENT_IMAGE' environment variable")
		os.Exit(1)
	}

	brokenContentImagePath = os.Getenv("BROKEN_CONTENT_IMAGE")

	if brokenContentImagePath == "" {
		fmt.Println("Please set the 'BROKEN_CONTENT_IMAGE' environment variable")
		os.Exit(1)
	}

	exitCode := m.Run()
	if exitCode == 0 || (exitCode > 0 && f.CleanUpOnError()) {
		if err = f.TearDown(); err != nil {
			log.Fatal(err)
		}
	}
	os.Exit(exitCode)
}

func TestApplyGenericRemediation(t *testing.T) {
	t.Parallel()
	f := framework.Global
	remName := "test-apply-generic-remediation"
	unstruct := &unstructured.Unstructured{}
	unstruct.SetUnstructuredContent(map[string]interface{}{
		"kind":       "ConfigMap",
		"apiVersion": "v1",
		"metadata": map[string]interface{}{
			"name":      "generic-rem-cm",
			"namespace": f.OperatorNamespace,
		},
		"data": map[string]interface{}{
			"key": "value",
		},
	})

	genericRem := &compv1alpha1.ComplianceRemediation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      remName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceRemediationSpec{
			ComplianceRemediationSpecMeta: compv1alpha1.ComplianceRemediationSpecMeta{
				Apply: true,
			},
			Current: compv1alpha1.ComplianceRemediationPayload{
				Object: unstruct,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), genericRem, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), genericRem)
	err = f.WaitForRemediationState(remName, f.OperatorNamespace, compv1alpha1.RemediationApplied)
	if err != nil {
		t.Fatal(err)
	}

	cm := &corev1.ConfigMap{}
	cmName := "generic-rem-cm"
	err = f.WaitForObjectToExist(cmName, f.OperatorNamespace, cm)
	if err != nil {
		t.Fatal(err)
	}
	val, ok := cm.Data["key"]
	if !ok || val != "value" {
		t.Fatalf("ComplianceRemediation '%s' generated a malformed ConfigMap", remName)
	}

	// verify object is marked as created by the operator
	if !compv1alpha1.RemediationWasCreatedByOperator(cm) {
		t.Fatalf("ComplianceRemediation '%s' is missing controller annotation '%s'",
			remName, compv1alpha1.RemediationCreatedByOperatorAnnotation)
	}
}

func TestPatchGenericRemediation(t *testing.T) {
	t.Parallel()
	f := framework.Global
	remName := framework.GetObjNameFromTest(t)
	cmName := remName
	cmKey := types.NamespacedName{
		Name:      cmName,
		Namespace: f.OperatorNamespace,
	}
	existingCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmKey.Name,
			Namespace: cmKey.Namespace,
		},
		Data: map[string]string{
			"existingKey": "existingData",
		},
	}

	if err := f.Client.Create(context.TODO(), existingCM, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), existingCM)

	cm := &corev1.ConfigMap{}
	err := f.WaitForObjectToExist(cmKey.Name, f.OperatorNamespace, cm)
	if err != nil {
		t.Fatal(err)
	}

	unstruct := &unstructured.Unstructured{}
	unstruct.SetUnstructuredContent(map[string]interface{}{
		"kind":       "ConfigMap",
		"apiVersion": "v1",
		"metadata": map[string]interface{}{
			"name":      cmKey.Name,
			"namespace": cmKey.Namespace,
		},
		"data": map[string]interface{}{
			"newKey": "newData",
		},
	})

	genericRem := &compv1alpha1.ComplianceRemediation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      remName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceRemediationSpec{
			ComplianceRemediationSpecMeta: compv1alpha1.ComplianceRemediationSpecMeta{
				Apply: true,
			},
			Current: compv1alpha1.ComplianceRemediationPayload{
				Object: unstruct,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err = f.Client.Create(context.TODO(), genericRem, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), genericRem)

	err = f.WaitForRemediationState(remName, f.OperatorNamespace, compv1alpha1.RemediationApplied)
	if err != nil {
		t.Fatal(err)
	}

	err = f.WaitForObjectToUpdate(cmKey.Name, f.OperatorNamespace, cm)
	if err != nil {
		t.Fatal(err)
	}

	// Old data should still be there
	val, ok := cm.Data["existingKey"]
	if !ok || val != "existingData" {
		t.Fatalf("ComplianceRemediation '%s' generated a malformed ConfigMap", remName)
	}

	// new data should be there too
	val, ok = cm.Data["newKey"]
	if !ok || val != "newData" {
		t.Fatalf("ComplianceRemediation '%s' generated a malformed ConfigMap", remName)
	}
}

func TestGenericRemediationFailsWithUnknownType(t *testing.T) {
	t.Parallel()
	f := framework.Global
	remName := "test-generic-remediation-fails-unknown"
	genericRem := &compv1alpha1.ComplianceRemediation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      remName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceRemediationSpec{
			ComplianceRemediationSpecMeta: compv1alpha1.ComplianceRemediationSpecMeta{
				Apply: true,
			},
			Current: compv1alpha1.ComplianceRemediationPayload{
				Object: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"kind":       "OopsyDoodle",
						"apiVersion": "foo.bar/v1",
						"metadata": map[string]interface{}{
							"name":      "unknown-remediation",
							"namespace": f.OperatorNamespace,
						},
						"data": map[string]interface{}{
							"key": "value",
						},
					},
				},
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), genericRem, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), genericRem)
	err = f.WaitForRemediationState(remName, f.OperatorNamespace, compv1alpha1.RemediationError)
	if err != nil {
		t.Fatal(err)
	}
}

// TestRemediationWithUnsetValueNeedsReview tests when a
// remediation needs a variable that the tailored profile doesn't set, the
// aggregator records the variable in the unset-value annotation. The operator
// must not apply such a remediation, even with apply set, and must report
// NeedsReview instead.
func TestRemediationWithUnsetValueNeedsReview(t *testing.T) {
	t.Parallel()
	f := framework.Global
	remName := framework.GetObjNameFromTest(t)
	cmName := remName
	unstruct := &unstructured.Unstructured{}
	unstruct.SetUnstructuredContent(map[string]interface{}{
		"kind":       "ConfigMap",
		"apiVersion": "v1",
		"metadata": map[string]interface{}{
			"name":      cmName,
			"namespace": f.OperatorNamespace,
		},
		"data": map[string]interface{}{
			"key": "value",
		},
	})

	rem := &compv1alpha1.ComplianceRemediation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      remName,
			Namespace: f.OperatorNamespace,
			Annotations: map[string]string{
				compv1alpha1.RemediationUnsetValueAnnotation: "var-multiple-time-servers",
			},
		},
		Spec: compv1alpha1.ComplianceRemediationSpec{
			ComplianceRemediationSpecMeta: compv1alpha1.ComplianceRemediationSpecMeta{
				Apply: true,
			},
			Current: compv1alpha1.ComplianceRemediationPayload{
				Object: unstruct,
			},
		},
	}
	err := f.Client.Create(context.TODO(), rem, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), rem)

	err = f.WaitForRemediationState(remName, f.OperatorNamespace, compv1alpha1.RemediationNeedsReview)
	if err != nil {
		t.Fatal(err)
	}

	// The operator labels remediations with unset values so that users can
	// find the ones that need a variable set.
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: remName, Namespace: f.OperatorNamespace}, rem)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rem.Labels[compv1alpha1.RemediationUnsetValueLabel]; !ok {
		t.Fatalf("ComplianceRemediation %s is missing label %s, labels: %v",
			remName, compv1alpha1.RemediationUnsetValueLabel, rem.Labels)
	}

	// The remediation must not have been applied.
	cm := &corev1.ConfigMap{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: cmName, Namespace: f.OperatorNamespace}, cm)
	if err == nil {
		t.Fatalf("ComplianceRemediation %s needs review, but its ConfigMap %s was created", remName, cmName)
	} else if !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
}

func TestVariableTemplate(t *testing.T) {
	f := framework.Global
	var baselineImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "variabletemplate")
	const requiredRule = "audit-profile-set"
	pbName := framework.GetObjNameFromTest(t)
	prefixName := func(profName, ruleBaseName string) string { return profName + "-" + ruleBaseName }

	// The remediation this test applies sets the cluster APIServer's audit
	// profile, which rolls out kube-apiserver, and deleting the remediation
	// doesn't undo it. Read the profile before anything can change it and put
	// it back when the test ends. t.Cleanup runs after the deferred deletes
	// below, so the binding that auto-applies the remediation is deleted by
	// then.
	apiServerBeforeRemediation := &configv1.APIServer{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: "cluster"}, apiServerBeforeRemediation); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		profile := apiServerBeforeRemediation.Spec.Audit.Profile
		if err := f.SetAPIServerAuditProfile(profile); err != nil {
			t.Errorf("failed to restore the APIServer audit profile %s: %s", profile, err)
		}
	})

	ocpPb, err := f.CreateProfileBundle(pbName, baselineImage, framework.OcpContentFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ocpPb)
	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}

	// Check that if the rule we are going to test is there
	requiredRuleName := prefixName(pbName, requiredRule)
	err, found := f.DoesRuleExist(f.OperatorNamespace, requiredRuleName)
	if err != nil {
		t.Fatal(err)
	} else if !found {
		t.Fatalf("expected rule %s not found", requiredRuleName)
	}

	suiteName := "audit-profile-set-test"
	scanName := "audit-profile-set-test"

	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "Audit-Profile-Set-Test",
			Description: "A test tailored profile to auto remediate audit profile set",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      prefixName(pbName, requiredRule),
					Rationale: "To be tested",
				},
			},
			SetValues: []compv1alpha1.VariableValueSpec{
				{
					Name:      prefixName(pbName, "var-openshift-audit-profile"),
					Rationale: "Value to be set",
					Value:     "WriteRequestBodies",
				},
			},
		},
	}

	createTPErr := f.Client.Create(context.TODO(), tp, nil)
	if createTPErr != nil {
		t.Fatal(createTPErr)
	}
	defer f.Client.Delete(context.TODO(), tp)

	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     suiteName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default-auto-apply",
		},
	}
	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	// We need to check that the remediation is auto-applied
	remName := "audit-profile-set-test-audit-profile-set"
	f.WaitForGenericRemediationToBeAutoApplied(remName, f.OperatorNamespace)

	// We can re-run the scan at this moment and check that it's now compliant
	// and it's reflected in a CheckResult
	err = f.ReRunScan(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	// Scan has been re-started
	log.Println("scan phase should be reset")
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseRunning, compv1alpha1.ResultNotAvailable)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure that all the scans in the suite have finished and are marked as Done
	log.Printf("waiting for scan to complete")
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("scan re-run has finished")

	// Now the check should be passing
	auditProfileSet := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-audit-profile-set", scanName),
			Namespace: f.OperatorNamespace,
		},
		ID:       "xccdf_org.ssgproject.content_rule_audit_profile_set",
		Status:   compv1alpha1.CheckResultPass,
		Severity: compv1alpha1.CheckResultSeverityMedium,
	}
	err = f.AssertHasCheck(suiteName, scanName, auditProfileSet)
	if err != nil {
		t.Fatal(err)
	}
}

// remediationSuffix matches the "-<number>" the operator appends when a single
// rule's fix produces more than one object. It mirrors remediationSuffixRegex
// in pkg/controller/complianceremediation.
var remediationSuffix = regexp.MustCompile(`-[0-9]+$`)

// TestAutoRemediate tests auto-remediation functionality with multiple rule types.
// This test covers the following scenarios:
// Tests auto-remediation with multiple remediation types simultaneously
//
//	        (file-based, audit rules, array values - whichever are non-compliant)
//	Tests scanning on a subset of nodes (the MachineConfigPool of the lane the test gets)
//	Tests ComplianceRemediation status transitions (Applied → PASS after rescan)
//	Tests array value remediations (chronyd with multiple NTP servers) and end-to-end workflow
//
// The test dynamically adapts to the environment by:
// 1. Scanning with multiple rules (file, audit, array value types)
// 2. Identifying which rules are non-compliant
// 3. Testing auto-remediation on all non-compliant rules
// 4. Verifying remediation status transitions and check results
// 5. Cleaning up all applied configurations
func TestAutoRemediate(t *testing.T) {
	t.Parallel()
	f := framework.Global
	pool := f.AcquireTestPool(t)
	// Name everything after the test so CRs can't collide with other tests
	// running in parallel lanes.
	suiteName := framework.GetObjNameFromTest(t)
	scanName := fmt.Sprintf("%s-%s", suiteName, pool.Name)

	// Use a ProfileBundle of its own rather than the shared rhcos4 one, so
	// concurrent lanes never share content objects.
	pb, pbErr := f.CreateProfileBundle(suiteName, contentImagePath, framework.RhcosContentFile)
	if pbErr != nil {
		t.Fatalf("failed to create ProfileBundle %s: %s", suiteName, pbErr)
	}
	defer f.Client.Delete(context.TODO(), pb)
	if err := f.WaitForProfileBundleStatus(suiteName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}

	// Each of these exercises a different kind of remediation, and a default
	// cluster fails all of them, so each is expected to produce at least one
	// ComplianceRemediation.
	remediatedRules := []compv1alpha1.RuleReferenceSpec{
		{
			Name:      fmt.Sprintf("%s-no-direct-root-logins", suiteName),
			Rationale: "Test file-based remediation",
		},
		{
			// Array value remediation
			Name:      fmt.Sprintf("%s-chronyd-or-ntpd-specify-multiple-servers", suiteName),
			Rationale: "Test array value remediation with multiple NTP servers",
		},
		{
			// Different remediation type (audit rules)
			Name:      fmt.Sprintf("%s-audit-rules-dac-modification-chmod", suiteName),
			Rationale: "Test audit rule remediation",
		},
	}

	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
			Annotations: map[string]string{
				compv1alpha1.ProductTypeAnnotation: "Node",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "Test Auto Remediate",
			Description: "A test tailored profile to auto remediate",
			EnableRules: remediatedRules,
		},
	}

	createTPErr := f.Client.Create(context.TODO(), tp, nil)
	if createTPErr != nil {
		t.Fatalf("failed to create TailoredProfile %s: %s", tp.Name, createTPErr)
	}
	defer f.Client.Delete(context.TODO(), tp)

	scanSettingName := suiteName + "-scan-setting"
	scanSetting := compv1alpha1.ScanSetting{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingName,
			Namespace: f.OperatorNamespace,
		},
		ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
			AutoApplyRemediations: true,
			Schedule:              "0 1 * * *",
		},
		ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
			Debug:   true,
			Timeout: "60m",
		},
		Roles: []string{pool.Name},
	}
	if err := f.Client.Create(context.TODO(), &scanSetting, nil); err != nil {
		t.Fatalf("failed to create ScanSetting %s: %s", scanSettingName, err)
	}
	defer f.Client.Delete(context.TODO(), &scanSetting)

	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     suiteName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     scanSettingName,
		},
	}
	err := f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatalf("failed to create ScanSettingBinding %s: %s", ssb.Name, err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	log.Printf("Waiting for scan %s to complete\n", scanName)
	err = f.WaitForSuiteScansStatusAnyResult(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatalf("Scan did not complete with an expected result: %v", err)
	}

	remediationList := &compv1alpha1.ComplianceRemediationList{}
	err = f.Client.List(context.TODO(), remediationList,
		client.InNamespace(f.OperatorNamespace),
		client.MatchingLabels{compv1alpha1.SuiteLabel: suiteName},
	)
	if err != nil {
		t.Fatal(err)
	}

	// The TailoredProfile deliberately enables rules a default cluster fails,
	// so we expect at least one remediation per rule. Fail rather than skip if
	// they stop generating remediations: skipping would let the test go green
	// against stale content while exercising nothing.
	ourRemediations := remediationList.Items
	if len(ourRemediations) < len(remediatedRules) {
		t.Fatalf("expected at least %d remediations for suite %s, got %d; the enabled rules may no longer generate remediations",
			len(remediatedRules), suiteName, len(ourRemediations))
	}

	log.Printf("Found %d remediation(s) to test: - multiple remediation types\n", len(ourRemediations))
	for _, rem := range ourRemediations {
		log.Printf("  - %s\n", rem.Name)
	}

	// Wait for all remediations to be auto-applied, processing them one at a time
	// Get fresh pool state for each remediation to handle multiple MCs efficiently
	var appliedRemediations []*compv1alpha1.ComplianceRemediation
	for i := range ourRemediations {
		rem := &ourRemediations[i]
		log.Printf("Waiting for remediation %d/%d: %s to be auto-applied\n", i+1, len(ourRemediations), rem.Name)

		// Get current pool state before waiting for this specific remediation
		// This ensures we're working with fresh state, especially important when multiple MCs are being applied
		currentPool := &mcfgv1.MachineConfigPool{}
		err = f.Client.Get(context.TODO(), types.NamespacedName{Name: pool.Name}, currentPool)
		if err != nil {
			t.Fatalf("Failed to get current MachineConfigPool state for remediation %s: %s", rem.Name, err)
		}

		err = f.WaitForRemediationToBeAutoApplied(rem.Name, f.OperatorNamespace, currentPool)
		if err != nil {
			t.Fatal(err)
		}

		// Verify ComplianceRemediation shows "Applied" status
		log.Printf("Verifying remediation %s is in Applied state\n", rem.Name)
		err = f.WaitForRemediationState(rem.Name, f.OperatorNamespace, compv1alpha1.RemediationApplied)
		if err != nil {
			t.Fatalf("Remediation %s not in Applied state: %s", rem.Name, err)
		}

		// Fetch updated remediation for cleanup
		updatedRem := &compv1alpha1.ComplianceRemediation{}
		err = f.Client.Get(context.TODO(), types.NamespacedName{Name: rem.Name, Namespace: f.OperatorNamespace}, updatedRem)
		if err != nil {
			t.Fatal(err)
		}
		appliedRemediations = append(appliedRemediations, updatedRem)
		log.Printf("Remediation %d/%d applied successfully: %s\n", i+1, len(ourRemediations), rem.Name)
	}

	log.Printf("All %d remediation(s) applied successfully\n", len(appliedRemediations))

	// We can re-run the scan at this moment and check that it's now compliant
	// and it's reflected in a CheckResult
	err = f.ReRunScan(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseRunning, compv1alpha1.ResultNotAvailable)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure that all the scans in the suite have finished and are marked as Done
	// After remediation, we expect COMPLIANT
	log.Printf("waiting for scan %s to finish\n", scanName)
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("scan %s re-run has finished with COMPLIANT result\n", scanName)

	// Verify all checks pass after remediation (Applied → PASS transition)
	log.Printf("Verifying all %d remediated checks are now PASS\n", len(appliedRemediations))
	checked := map[string]bool{}
	for _, rem := range appliedRemediations {
		// A rule whose fix yields several objects gets one remediation per
		// object, named <scan>-<rule>, <scan>-<rule>-1, <scan>-<rule>-2 and so
		// on, but they all share the single <scan>-<rule> ComplianceCheckResult.
		// Drop the suffix to get the check name, and only look each one up once.
		checkName := remediationSuffix.ReplaceAllString(rem.Name, "")
		if checked[checkName] {
			continue
		}
		checked[checkName] = true
		log.Printf("Verifying check %s passed\n", checkName)

		// Get the check result
		checkResult := &compv1alpha1.ComplianceCheckResult{}
		err = f.Client.Get(context.TODO(), types.NamespacedName{Name: checkName, Namespace: f.OperatorNamespace}, checkResult)
		if err != nil {
			t.Fatalf("Failed to get ComplianceCheckResult %s: %s", checkName, err)
		}

		if checkResult.Status != compv1alpha1.CheckResultPass {
			t.Fatalf("Expected check %s to PASS after remediation, got %s", checkName, checkResult.Status)
		}
		log.Printf("Check %s is PASS\n", checkName)
	}

	// The test should not leave junk around, let's unapply all remediations and wait
	// for the nodes to stabilize again.
	// Unapply remediations one at a time and wait for pool to stabilize after each
	// to avoid timeout when unapplying multiple remediations simultaneously
	log.Printf("Unapplying %d remediation(s) one at a time\n", len(appliedRemediations))

	// Stop auto-apply first: the suite controller sets every remediation of
	// an auto-apply suite back to applied (and pauses the pool) whenever it
	// reconciles the suite.
	if err := f.DisableScanSettingAutoApply(scanSettingName, suiteName, f.OperatorNamespace); err != nil {
		t.Fatalf("failed to disable auto-apply for suite %s: %s", suiteName, err)
	}

	for i, rem := range appliedRemediations {
		log.Printf("Unapplying remediation %d/%d: %s\n", i+1, len(appliedRemediations), rem.Name)
		err = f.UnApplyRemediationAndCheck(f.OperatorNamespace, rem.Name, pool.Name)
		if err != nil {
			t.Fatalf("Failed to unapply remediation %s: %s", rem.Name, err)
		}
		log.Printf("Successfully unapplied remediation %s\n", rem.Name)
	}

	log.Printf("Successfully unapplied all remediations and pool has stabilized")

	// ..as well as the nodes
	err = f.WaitForNodesToBeReadyInPool(pool.Name)
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnapplyRemediation(t *testing.T) {
	t.Parallel()
	f := framework.Global
	pool := f.AcquireTestPool(t)
	// The remediation MachineConfig is cluster-scoped and named after the scan
	// (75-<scan>-<rule>), so the scan name carries the test and the lane.
	suiteName := framework.GetObjNameFromTest(t)
	workerScanName := fmt.Sprintf("%s-%s", suiteName, pool.Name)

	exampleComplianceSuite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: false,
			},
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						NodeSelector: pool.NodeRoleSelector(),
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
						},
					},
					Name: workerScanName,
				},
			},
		},
	}

	err := f.Client.Create(context.TODO(), exampleComplianceSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), exampleComplianceSuite)

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	// Pause the MC so that we have only one reboot
	err = f.PauseMachinePool(pool.Name)
	if err != nil {
		t.Fatal(err)
	}

	// Apply both remediations
	workersNoRootLoginsRemName := fmt.Sprintf("%s-no-direct-root-logins", workerScanName)
	err = f.ApplyRemediationAndCheck(f.OperatorNamespace, workersNoRootLoginsRemName, pool.Name)
	if err != nil {
		log.Printf("WARNING: Got an error while applying remediation '%s': %v\n", workersNoRootLoginsRemName, err)
	}
	log.Printf("remediation %s applied", workersNoRootLoginsRemName)

	workersNoEmptyPassRemName := fmt.Sprintf("%s-no-empty-passwords", workerScanName)
	err = f.ApplyRemediationAndCheck(f.OperatorNamespace, workersNoEmptyPassRemName, pool.Name)
	if err != nil {
		log.Printf("WARNING: Got an error while applying remediation '%s': %v\n", workersNoEmptyPassRemName, err)
	}
	log.Printf("remediation %s applied", workersNoEmptyPassRemName)

	// resume the MCP so that the remediation gets applied
	f.ResumeMachinePool(pool.Name)

	err = f.WaitForNodesToBeReadyInPool(pool.Name)
	if err != nil {
		t.Fatal(err)
	}

	// Get the resulting MC
	mcName := types.NamespacedName{Name: fmt.Sprintf("75-%s", workersNoEmptyPassRemName)}
	mcBoth := &mcfgv1.MachineConfig{}
	err = f.Client.Get(context.TODO(), mcName, mcBoth)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), mcBoth)
	log.Printf("MachineConfig %s exists\n", mcName.Name)

	// Revert one remediation. The MC should stay, but its generation should bump
	log.Printf("reverting remediation %s\n", workersNoEmptyPassRemName)
	err = f.UnApplyRemediationAndCheck(f.OperatorNamespace, workersNoEmptyPassRemName, pool.Name)
	if err != nil {
		log.Printf("WARNING: Got an error while unapplying remediation '%s': %v\n", workersNoEmptyPassRemName, err)
	}
	log.Printf("remediation %s reverted\n", workersNoEmptyPassRemName)

	// When we unapply the second remediation, the MC should be deleted, too
	log.Printf("reverting remediation %s", workersNoRootLoginsRemName)
	err = f.UnApplyRemediationAndCheck(f.OperatorNamespace, workersNoRootLoginsRemName, pool.Name)
	if err != nil {
		log.Printf("WARNING: Got an error while unapplying remediation '%s': %v\n", workersNoEmptyPassRemName, err)
	}

	log.Printf("remediation %s reverted", workersNoEmptyPassRemName)

	log.Printf("no remediation-based MachineConfigs should exist now")
	mcShouldntExist := &mcfgv1.MachineConfig{}
	err = f.Client.Get(context.TODO(), mcName, mcShouldntExist)
	if err == nil {
		t.Fatalf("found an unexpected MachineConfig: %s", err)
	}
}

func TestUpdateRemediation(t *testing.T) {
	t.Parallel()
	f := framework.Global
	pool := f.AcquireTestPool(t)
	origSuiteName := framework.GetObjNameFromTest(t)
	workerScanName := fmt.Sprintf("%s-%s", origSuiteName, pool.Name)

	var (
		origImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "rem_mod_base")
		modImage  = fmt.Sprintf("%s:%s", brokenContentImagePath, "rem_mod_change")
	)

	pbName := framework.GetObjNameFromTest(t)
	rhcosPb, err := f.CreateProfileBundle(pbName, origImage, framework.RhcosContentFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), rhcosPb)

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}

	pbNameMod := fmt.Sprintf("%s-%s", pbName, "mod")
	rhcosPbMod, err := f.CreateProfileBundle(pbNameMod, modImage, framework.RhcosContentFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), rhcosPbMod)
	if err := f.WaitForProfileBundleStatus(pbNameMod, compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}

	origSuite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      origSuiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: false,
			},
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: origImage,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Rule:         "xccdf_org.ssgproject.content_rule_no_empty_passwords",
						Content:      framework.RhcosContentFile,
						NodeSelector: pool.NodeRoleSelector(),
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
						},
					},
					Name: workerScanName,
				},
			},
		},
	}

	err = f.Client.Create(context.TODO(), origSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), origSuite)

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, origSuiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	workersNoEmptyPassRemName := fmt.Sprintf("%s-no-empty-passwords", workerScanName)
	err = f.ApplyRemediationAndCheck(f.OperatorNamespace, workersNoEmptyPassRemName, pool.Name)
	if err != nil {
		log.Printf("WARNING: Got an error while applying remediation '%s': %v", workersNoEmptyPassRemName, err)
	}
	log.Printf("remediation %s applied\n", workersNoEmptyPassRemName)

	err = f.WaitForNodesToBeReadyInPool(pool.Name)
	if err != nil {
		t.Fatalf("failed waiting for nodes to reboot after applying remedation: %s", err)
	}

	// Now update the suite with a different image that contains different remediations
	if err := f.UpdateSuiteContentImage(modImage, origSuiteName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}
	log.Printf("suite %s updated with a new image\n", origSuiteName)

	err = f.ReRunScan(workerScanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, origSuiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertRemediationIsObsolete(f.OperatorNamespace, workersNoEmptyPassRemName)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("will remove obsolete data from remediation\n")
	renderedMcName := fmt.Sprintf("75-%s", workersNoEmptyPassRemName)
	err = f.RemoveObsoleteRemediationAndCheck(f.OperatorNamespace, workersNoEmptyPassRemName, renderedMcName, pool.Name)
	if err != nil {
		t.Fatal(err)
	}

	err = f.WaitForNodesToBeReadyInPool(pool.Name)
	if err != nil {
		t.Fatalf("failed waiting for nodes to reboot after applying MachineConfig: %s", err)
	}

	// Now the remediation is no longer obsolete
	err = f.AssertRemediationIsCurrent(f.OperatorNamespace, workersNoEmptyPassRemName)
	if err != nil {
		t.Fatal(err)
	}

	// Finally clean up by removing the remediation and waiting for the nodes to reboot one more time
	err = f.UnApplyRemediationAndCheck(f.OperatorNamespace, workersNoEmptyPassRemName, pool.Name)
	if err != nil {
		t.Fatal(err)
	}

	err = f.WaitForNodesToBeReadyInPool(pool.Name)
	if err != nil {
		t.Fatalf("failed waiting for nodes to reboot after unapplying MachineConfig: %s", err)
	}
}

func TestKubeletConfigRemediation(t *testing.T) {
	t.Parallel()
	f := framework.Global
	pool := f.AcquireTestPool(t)
	var baselineImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "new_kubeletconfig")
	const requiredRule = "kubelet-enable-streaming-connections"
	pbName := framework.GetObjNameFromTest(t)
	prefixName := func(profName, ruleBaseName string) string { return profName + "-" + ruleBaseName }

	ocpPb, err := f.CreateProfileBundle(pbName, baselineImage, framework.OcpContentFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ocpPb)
	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}

	// Check that if the rule we are going to test is there
	requiredRuleName := prefixName(pbName, requiredRule)
	requiredVersionRuleName := prefixName(pbName, "version-detect-in-ocp")
	requiredVariableName := prefixName(pbName, "var-streaming-connection-timeouts")
	// The "-node" suffix makes the TailoredProfile, which mixes node and
	// platform rules, a node profile (see the TailoredProfile controller).
	suiteName := framework.GetObjNameFromTest(t) + "-node"

	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "kubelet-remediation-test-node",
			Description: "A test tailored profile to test kubelet remediation",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      requiredRuleName,
					Rationale: "To be tested",
				},
				{
					Name:      requiredVersionRuleName,
					Rationale: "To be tested",
				},
			},
			SetValues: []compv1alpha1.VariableValueSpec{
				{
					Name:      requiredVariableName,
					Rationale: "Value to be set",
					Value:     "8h0m0s",
				},
			},
		},
	}
	createTPErr := f.Client.Create(context.TODO(), tp, nil)
	if createTPErr != nil {
		t.Fatal(createTPErr)
	}
	defer f.Client.Delete(context.TODO(), tp)

	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     suiteName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     pool.AutoApplyScanSetting,
		},
	}

	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The KubeletConfig is per pool (compliance-operator-kubelet-<pool>), not
	// per test, so remove it and let the lane roll back before the lane is
	// released; otherwise the next test on this lane inherits it.
	defer func() {
		if err := f.DeleteScanSettingBindingAndWaitForCleanup(ssb); err != nil {
			t.Errorf("failed to clean up ScanSettingBinding %s: %s", ssb.Name, err)
		}
		if err := f.DeleteKubeletConfigAndWaitForPool(pool.Name); err != nil {
			t.Errorf("failed to remove KubeletConfig for pool %s: %s", pool.Name, err)
		}
	}()

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	scanName := suiteName + "-" + pool.Name

	// We need to check that the remediation is auto-applied and save
	// the object so we can delete it later
	remName := scanName + "-kubelet-enable-streaming-connections"
	err = f.WaitForGenericRemediationToBeAutoAppliedInPool(remName, f.OperatorNamespace, pool.Name)
	if err != nil {
		t.Fatal(err)
	}

	err = f.ReRunScan(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	// Scan has been re-started
	log.Printf("scan phase should be reset")
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseRunning, compv1alpha1.ResultNotAvailable)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure that all the scans in the suite have finished and are marked as Done
	log.Printf("let's wait for it to be done now")
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("scan re-run has finished")

	// Now the check should be passing
	checkResult := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-kubelet-enable-streaming-connections", scanName),
			Namespace: f.OperatorNamespace,
		},
		ID:       "xccdf_org.ssgproject.content_rule_kubelet_enable_streaming_connections",
		Status:   compv1alpha1.CheckResultPass,
		Severity: compv1alpha1.CheckResultSeverityMedium,
	}
	err = f.AssertHasCheck(suiteName, scanName, checkResult)
	if err != nil {
		t.Fatal(err)
	}

	// The remediation must not be Outdated
	remediation := &compv1alpha1.ComplianceRemediation{}
	remNsName := types.NamespacedName{
		Name:      remName,
		Namespace: f.OperatorNamespace,
	}
	err = f.Client.Get(context.TODO(), remNsName, remediation)
	if err != nil {
		t.Fatalf("couldn't get remediation %s: %s", remName, err)
	}
	if remediation.Status.ApplicationState != compv1alpha1.RemediationApplied {
		t.Fatalf("remediation %s is not applied, but %s", remName, remediation.Status.ApplicationState)
	}
}

func TestRuntimeSSHConfigWithRemediation(t *testing.T) {
	t.Parallel()
	f := framework.Global
	pool := f.AcquireTestPool(t)

	baselineImage := fmt.Sprintf("%s:%s", brokenContentImagePath, "runtime_sshd")
	pbName := framework.GetObjNameFromTest(t)

	rhcos4Pb, err := f.CreateProfileBundle(pbName, baselineImage, framework.RhcosContentFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), rhcos4Pb)
	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}

	// This test applies an SSH remediation and verifies runtime checks still work
	suiteName := framework.GetObjNameFromTest(t)
	scanName := fmt.Sprintf("%s-%s", suiteName, pool.Name)

	suite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: true,
			},
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: baselineImage,
						Profile:      "xccdf_org.ssgproject.content_profile_e8",
						Rule:         "xccdf_org.ssgproject.content_rule_sshd_disable_gssapi_auth",
						Content:      framework.RhcosContentFile,
						NodeSelector: pool.NodeRoleSelector(),
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
						},
					},
					Name: scanName,
				},
			},
		},
	}

	if err := f.Client.Create(context.TODO(), suite, nil); err != nil {
		t.Fatalf("failed to create ComplianceSuite: %s", err)
	}
	defer f.Client.Delete(context.TODO(), suite)

	// Get the MachineConfigPool before remediation
	poolBeforeRemediation := &mcfgv1.MachineConfigPool{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: pool.Name}, poolBeforeRemediation); err != nil {
		t.Fatal(err)
	}

	// Wait for initial scan to complete - it should be non-compliant
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		// Might already be compliant if previously remediated
		if err2 := f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant); err2 != nil {
			t.Fatalf("initial scan did not complete: %v", err)
		}
		t.Log("System already compliant, skipping remediation test")
		return
	}

	// The sshd_disable_gssapi_auth fix ships two MachineConfig variants gated by
	// OCP version (<4.13.0 and >=4.13.0). The operator only generates a
	// ComplianceRemediation for the variant matching the cluster, so the applied
	// remediation name carries a version-dependent index suffix (e.g. "-1" for the
	// >=4.13.0 variant). Hard-coding the base name (the <4.13.0 variant) meant the
	// test waited on a remediation that is never created on modern clusters, so
	// WaitForRemediationToBeAutoApplied blocked for the full 30m Timeout and
	// silently timed out every run. The suite scan already reached DONE above, so
	// any remediation for this scan is already created - discover it by scan label
	// and wait for the one that actually exists.
	remList := &compv1alpha1.ComplianceRemediationList{}
	if err := f.Client.List(context.TODO(), remList, client.InNamespace(f.OperatorNamespace),
		client.MatchingLabels{compv1alpha1.ComplianceScanLabel: scanName}); err != nil {
		t.Fatalf("failed to list remediations for scan %s: %v", scanName, err)
	}
	if len(remList.Items) == 0 {
		t.Logf("No ComplianceRemediation generated for scan %s; continuing", scanName)
	}
	for i := range remList.Items {
		if err := f.WaitForRemediationToBeAutoApplied(remList.Items[i].Name, f.OperatorNamespace, poolBeforeRemediation); err != nil {
			t.Logf("Remediation %s might not be needed or already applied: %v", remList.Items[i].Name, err)
		}
	}

	// Re-run the scan to verify compliance with runtime checking
	if err := f.ReRunScan(scanName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}

	// Wait for re-scan to complete - should be compliant now
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant); err != nil {
		t.Logf("WARNING: Re-scan was not compliant after remediation: %v", err)
	}

	// Verify the runtime config was still created and used in the re-scan
	t.Log("Verifying runtime SSH config was used in re-scan after remediation")

	// Get the check result for the SSH rule
	checkName := fmt.Sprintf("%s-sshd-disable-gssapi-auth", scanName)
	check := &compv1alpha1.ComplianceCheckResult{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{
		Name:      checkName,
		Namespace: f.OperatorNamespace,
	}, check); err != nil {
		t.Logf("Could not get check result %s: %v", checkName, err)
	} else {
		t.Logf("SSH check after remediation - Status: %s", check.Status)
		if check.Status == compv1alpha1.CheckResultPass {
			t.Log("SUCCESS: SSH configuration check passed after remediation (runtime config verified)")
		}
	}

	// Clean up any remediations that were applied. Stop the suite from
	// auto-applying first: otherwise the suite controller re-applies each
	// remediation as soon as it's unapplied, and the pool never drops its
	// MachineConfig.
	if err := f.DisableSuiteAutoApply(suiteName, f.OperatorNamespace); err != nil {
		t.Fatalf("failed to disable auto-apply on suite %s: %s", suiteName, err)
	}
	for i := range remList.Items {
		remName := remList.Items[i].Name
		rem := &compv1alpha1.ComplianceRemediation{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{
			Name:      remName,
			Namespace: f.OperatorNamespace,
		}, rem); err != nil {
			continue
		}
		// Unapply the remediation
		// A failure here fails the test, which takes the lane out of
		// rotation (AcquireTestPool) instead of passing it on dirty.
		if err := f.UnApplyRemediationAndCheck(f.OperatorNamespace, remName, pool.Name); err != nil {
			t.Errorf("Could not unapply remediation %s: %v", remName, err)
		}

		// Wait for nodes to be ready again
		if err := f.WaitForNodesToBeReadyInPool(pool.Name); err != nil {
			t.Errorf("Nodes did not become ready after remediation removal: %v", err)
		}
	}

	t.Log("Runtime SSH configuration with remediation test completed")
}

func TestResultServerTolerationsOnTaintedNode(t *testing.T) {
	t.Parallel()
	f := framework.Global
	// Taint the test's own lane node and keep the scan and its result server
	// on that lane, so the NoExecute taint doesn't evict pods from a shared
	// worker and the result server can only be scheduled on the tainted node.
	pool := f.AcquireTestPool(t)
	laneNodes, err := f.GetNodesWithSelector(pool.NodeRoleSelector())
	if err != nil {
		t.Fatal(err)
	}
	if len(laneNodes) == 0 {
		t.Fatalf("no node in test pool %s", pool.Name)
	}
	workerNode := &laneNodes[0]

	defaultScanSetting := &compv1alpha1.ScanSetting{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: "default", Namespace: f.OperatorNamespace}, defaultScanSetting); err != nil {
		t.Fatal(err)
	}

	taintKey := "key1"
	scanSettingName := framework.GetObjNameFromTest(t) + "-lane-ss"
	customScanSetting := defaultScanSetting.DeepCopy()
	customScanSetting.ObjectMeta = metav1.ObjectMeta{Name: scanSettingName, Namespace: f.OperatorNamespace}
	customScanSetting.Roles = []string{pool.Name}
	customScanSetting.RawResultStorage.NodeSelector = pool.NodeRoleSelector()
	customScanSetting.RawResultStorage.Tolerations = []corev1.Toleration{
		{Effect: corev1.TaintEffectNoSchedule, Key: "node-role.kubernetes.io/master", Operator: corev1.TolerationOpExists},
		{Effect: corev1.TaintEffectNoExecute, Key: "node.kubernetes.io/not-ready", Operator: corev1.TolerationOpExists, TolerationSeconds: &[]int64{300}[0]},
		{Effect: corev1.TaintEffectNoExecute, Key: "node.kubernetes.io/unreachable", Operator: corev1.TolerationOpExists, TolerationSeconds: &[]int64{300}[0]},
		{Effect: corev1.TaintEffectNoSchedule, Key: "node.kubernetes.io/memory-pressure", Operator: corev1.TolerationOpExists},
		{Effect: corev1.TaintEffectNoExecute, Key: taintKey, Value: "value1", Operator: corev1.TolerationOpEqual},
	}
	if err := f.Client.Create(context.TODO(), customScanSetting, nil); err != nil {
		t.Fatalf("failed to create ScanSetting for test pool %s: %v", pool.Name, err)
	}
	defer f.Client.Delete(context.TODO(), customScanSetting)

	taint := corev1.Taint{Key: taintKey, Value: "value1", Effect: corev1.TaintEffectNoExecute}
	if err := f.TaintNode(workerNode, taint); err != nil {
		t.Fatalf("failed to taint node %s: %v", workerNode.Name, err)
	}
	defer f.UntaintNode(workerNode.Name, taintKey)

	labeledNode := &corev1.Node{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: workerNode.Name}, labeledNode); err != nil {
		t.Fatalf("failed to get node %s before labeling: %v", workerNode.Name, err)
	}
	if labeledNode.Labels == nil {
		labeledNode.Labels = make(map[string]string)
	}
	labeledNode.Labels["taint"] = "true"
	if err := f.Client.Update(context.TODO(), labeledNode); err != nil {
		t.Fatalf("failed to label node %s: %v", workerNode.Name, err)
	}
	defer func() {
		unlabeledNode := &corev1.Node{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: workerNode.Name}, unlabeledNode); err == nil {
			delete(unlabeledNode.Labels, "taint")
			f.Client.Update(context.TODO(), unlabeledNode)
		}
	}()

	b := framework.GetObjNameFromTest(t) + "-tolerations"
	ssb := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{Name: b, Namespace: f.OperatorNamespace},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     "ocp4-high-node",
				Kind:     "Profile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			Name:     scanSettingName,
			Kind:     "ScanSetting",
			APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}
	if err := f.Client.Create(context.TODO(), &ssb, nil); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.DeleteScanSettingBindingAndWaitForCleanup(&ssb); err != nil {
			t.Logf("cleanup ScanSettingBinding %s: %v", b, err)
		}
	}()

	resultServerNodeNames, err := f.WaitForResultServerPodsWithNodeSelector(pool.NodeRoleSelector(), "ocp4-high-node-"+pool.Name)
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("result server pods scheduled on nodes: %v", resultServerNodeNames)
	found := false
	for _, name := range resultServerNodeNames {
		if name == workerNode.Name {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no result server pod scheduled on tainted worker node %s; scheduled on: %v", workerNode.Name, resultServerNodeNames)
	}
	if err := f.WaitForSuiteScansStatusAnyResult(f.OperatorNamespace, b, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant, compv1alpha1.ResultCompliant); err != nil {
		t.Fatalf("ComplianceSuite %s did not complete: %v", b, err)
	}
}
