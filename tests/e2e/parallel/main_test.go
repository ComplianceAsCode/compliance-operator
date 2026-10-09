package parallel_e2e

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"testing"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	configv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var brokenContentImagePath string
var contentImagePath string

func TestMain(m *testing.M) {
	f := framework.NewFramework()
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

func TestProfileVersion(t *testing.T) {
	t.Parallel()
	f := framework.Global

	profile := &compv1alpha1.Profile{}
	// We know this profile has a version and it's set in the ComplianceAsCode/content
	profileName := "ocp4-cis"
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: f.OperatorNamespace, Name: profileName}, profile); err != nil {
		t.Fatalf("failed to get profile %s: %s", profileName, err)
	}
	if profile.Version == "" {
		t.Fatalf("expected profile %s to have version set", profileName)
	}
}

func TestProfileBundleXCCDFGroupsAnnotation(t *testing.T) {
	t.Parallel()
	f := framework.Global

	pbName := framework.GetObjNameFromTest(t)
	pb, err := f.CreateProfileBundle(pbName, contentImagePath, framework.RhcosContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle: %s", err)
	}
	defer f.Client.Delete(context.TODO(), pb)

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("failed waiting for the ProfileBundle to become available: %s", err)
	}

	// Get the updated ProfileBundle to check annotations
	updatedPb := &compv1alpha1.ProfileBundle{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: pbName, Namespace: f.OperatorNamespace}, updatedPb); err != nil {
		t.Fatalf("failed to get ProfileBundle %s: %s", pbName, err)
	}

	annotations := updatedPb.GetAnnotations()
	if annotations == nil {
		t.Fatalf("ProfileBundle %s has no annotations", pbName)
	}

	groupsAnnotation, exists := annotations[compv1alpha1.XCCDFGroupsAnnotation]
	if !exists {
		t.Fatalf("ProfileBundle %s is missing the %s annotation", pbName, compv1alpha1.XCCDFGroupsAnnotation)
	}

	if groupsAnnotation == "" {
		t.Fatalf("ProfileBundle %s has empty %s annotation", pbName, compv1alpha1.XCCDFGroupsAnnotation)
	}

	// Verify it's a comma-separated list with at least one group
	groups := strings.Split(groupsAnnotation, ",")
	if len(groups) == 0 {
		t.Fatalf("ProfileBundle %s has no groups in %s annotation", pbName, compv1alpha1.XCCDFGroupsAnnotation)
	}

	t.Logf("ProfileBundle %s has %d XCCDF groups", pbName, len(groups))
}

func TestProfileModification(t *testing.T) {
	t.Parallel()
	f := framework.Global
	const (
		removedRule         = "chronyd-no-chronyc-network"
		unlinkedRule        = "chronyd-client-only"
		moderateProfileName = "moderate"
	)
	var (
		baselineImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_baseline")
		modifiedImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_mod")
	)

	prefixName := func(profName, ruleBaseName string) string { return profName + "-" + ruleBaseName }

	pbName := framework.GetObjNameFromTest(t)
	origPb, err := f.CreateProfileBundle(pbName, baselineImage, framework.RhcosContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle: %s", err)
	}
	// This should get cleaned up at the end of the test
	defer f.Client.Delete(context.TODO(), origPb)

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("failed waiting for the ProfileBundle to become available: %s", err)
	}
	if err := f.AssertMustHaveParsedProfiles(pbName, string(compv1alpha1.ScanTypeNode), "redhat_enterprise_linux_coreos_4"); err != nil {
		t.Fatalf("failed checking profiles in ProfileBundle: %s", err)
	}

	// Check that the rule we removed exists in the original profile
	removedRuleName := prefixName(pbName, removedRule)
	err, found := f.DoesRuleExist(origPb.Namespace, removedRuleName)
	if err != nil {
		t.Fatal(err)
	} else if found != true {
		t.Fatalf("expected rule %s to exist in namespace %s", removedRuleName, origPb.Namespace)
	}

	// Check that the rule we unlined in the modified profile is linked in the original
	profileName := prefixName(pbName, moderateProfileName)
	profilePreUpdate := &compv1alpha1.Profile{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: origPb.Namespace, Name: profileName}, profilePreUpdate); err != nil {
		t.Fatalf("failed to get profile %s", profileName)
	}
	unlinkedRuleName := prefixName(pbName, unlinkedRule)
	found = framework.IsRuleInProfile(unlinkedRuleName, profilePreUpdate)
	if found == false {
		t.Fatalf("failed to find rule %s in profile %s", unlinkedRule, profileName)
	}

	tpName1 := fmt.Sprintf("%s-tp-before-update", pbName)
	tp1 := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName1,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "TestProfileModification Before Update",
			Description: "TailoredProfile created before ProfileBundle update",
			Extends:     profileName,
		},
	}
	if err := f.Client.Create(context.TODO(), tp1, nil); err != nil {
		t.Fatalf("failed to create TailoredProfile %s: %s", tpName1, err)
	}
	defer f.Client.Delete(context.TODO(), tp1)
	if err := f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpName1, compv1alpha1.TailoredProfileStateReady); err != nil {
		t.Fatal(err)
	}

	// update the image with a new hash
	modPb := origPb.DeepCopy()
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: modPb.Namespace, Name: modPb.Name}, modPb); err != nil {
		t.Fatalf("failed to get ProfileBundle %s", modPb.Name)
	}

	modPb.Spec.ContentImage = modifiedImage
	if err := f.Client.Update(context.TODO(), modPb); err != nil {
		t.Fatalf("failed to update ProfileBundle %s: %s", modPb.Name, err)
	}

	// Wait for the update to happen, the PB will flip first to pending, then to valid
	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("failed to parse ProfileBundle %s: %s", pbName, err)
	}

	if err := f.AssertProfileBundleMustHaveParsedRules(pbName); err != nil {
		t.Fatal(err)
	}

	// We removed this rule in the update, is must no longer exist
	err, found = f.DoesRuleExist(origPb.Namespace, removedRuleName)
	if err != nil {
		t.Fatal(err)
	} else if found {
		t.Fatalf("rule %s unexpectedly found", removedRuleName)
	}

	// This rule was unlinked
	profilePostUpdate := &compv1alpha1.Profile{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: origPb.Namespace, Name: profileName}, profilePostUpdate); err != nil {
		t.Fatalf("failed to get profile %s: %s", profileName, err)
	}
	framework.IsRuleInProfile(unlinkedRuleName, profilePostUpdate)
	if found {
		t.Fatalf("rule %s unexpectedly found", unlinkedRuleName)
	}

	tpName2 := fmt.Sprintf("%s-tp-after-update", pbName)
	tp2 := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName2,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "TestProfileModification After Update",
			Description: "TailoredProfile created after ProfileBundle update",
			Extends:     profileName,
		},
	}
	if err := f.Client.Create(context.TODO(), tp2, nil); err != nil {
		t.Fatalf("failed to create TailoredProfile %s: %s", tpName2, err)
	}
	defer f.Client.Delete(context.TODO(), tp2)
	if err := f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpName2, compv1alpha1.TailoredProfileStateReady); err != nil {
		t.Fatal(err)
	}
}

func TestProfileISTagUpdate(t *testing.T) {
	t.Parallel()
	f := framework.Global
	const (
		removedRule         = "chronyd-no-chronyc-network"
		unlinkedRule        = "chronyd-client-only"
		moderateProfileName = "moderate"
	)
	var (
		baselineImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_baseline")
		modifiedImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_mod")
	)

	prefixName := func(profName, ruleBaseName string) string { return profName + "-" + ruleBaseName }

	pbName := framework.GetObjNameFromTest(t)
	iSName := pbName

	s, err := f.CreateImageStream(iSName, f.OperatorNamespace, baselineImage)
	if err != nil {
		t.Fatalf("failed to create image stream %s", iSName)
	}
	defer f.Client.Delete(context.TODO(), s)

	baselineImage = fmt.Sprintf("%s:%s", iSName, "latest")
	pb, err := f.CreateProfileBundle(pbName, baselineImage, framework.RhcosContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle: %s", err)
	}
	defer f.Client.Delete(context.TODO(), pb)

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("failed waiting for the ProfileBundle to become available: %s", err)
	}
	if err := f.AssertMustHaveParsedProfiles(pbName, string(compv1alpha1.ScanTypeNode), "redhat_enterprise_linux_coreos_4"); err != nil {
		t.Fatalf("failed checking profiles in ProfileBundle: %s", err)
	}

	// Check that the rule we removed exists in the original profile
	removedRuleName := prefixName(pbName, removedRule)
	err, found := f.DoesRuleExist(pb.Namespace, removedRuleName)
	if err != nil {
		t.Fatal(err)
	} else if !found {
		t.Fatalf("failed to find rule %s in ProfileBundle %s", removedRuleName, pbName)
	}

	// Check that the rule we unlined in the modified profile is linked in the original
	profilePreUpdate := &compv1alpha1.Profile{}
	profileName := prefixName(pbName, moderateProfileName)
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: pb.Namespace, Name: profileName}, profilePreUpdate); err != nil {
		t.Fatalf("failed to get profile %s", profileName)
	}
	unlinkedRuleName := prefixName(pbName, unlinkedRule)
	found = framework.IsRuleInProfile(unlinkedRuleName, profilePreUpdate)
	if !found {
		t.Fatalf("failed to find rule %s in ProfileBundle %s", unlinkedRuleName, pbName)
	}

	// Update the reference in the image stream
	if err := f.UpdateImageStreamTag(iSName, modifiedImage, f.OperatorNamespace); err != nil {
		t.Fatalf("failed to update image stream %s: %s", iSName, err)
	}

	modifiedImageDigest, err := f.GetImageStreamUpdatedDigest(iSName, f.OperatorNamespace)
	if err != nil {
		t.Fatalf("failed to get digest for image stream %s: %s", iSName, err)
	}

	// Note that when an update happens through an imagestream tag, the operator doesn't get
	// a notification about it... It all happens on the Kube Deployment's side.
	// So we don't need to wait for the profile bundle's statuses
	if err := f.WaitForDeploymentContentUpdate(pbName, modifiedImageDigest); err != nil {
		t.Fatalf("failed waiting for content to update: %s", err)
	}

	if err := f.AssertProfileBundleMustHaveParsedRules(pbName); err != nil {
		t.Fatal(err)
	}

	// We removed this rule in the update, it must no longer exist
	err, found = f.DoesRuleExist(pb.Namespace, removedRuleName)
	if err != nil {
		t.Fatal(err)
	} else if found {
		t.Fatalf("rule %s unexpectedly found", removedRuleName)
	}

	// This rule was unlinked
	profilePostUpdate := &compv1alpha1.Profile{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: pb.Namespace, Name: profileName}, profilePostUpdate); err != nil {
		t.Fatalf("failed to get profile %s", profileName)
	}
	found = framework.IsRuleInProfile(unlinkedRuleName, profilePostUpdate)
	if found {
		t.Fatalf("rule %s unexpectedly found", unlinkedRuleName)
	}
}

func TestProfileISTagOtherNs(t *testing.T) {
	t.Parallel()
	f := framework.Global
	const (
		removedRule         = "chronyd-no-chronyc-network"
		unlinkedRule        = "chronyd-client-only"
		moderateProfileName = "moderate"
	)
	var (
		baselineImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_baseline")
		modifiedImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_mod")
	)

	prefixName := func(profName, ruleBaseName string) string { return profName + "-" + ruleBaseName }

	pbName := framework.GetObjNameFromTest(t)
	iSName := pbName
	otherNs := "openshift"

	stream, err := f.CreateImageStream(iSName, otherNs, baselineImage)
	if err != nil {
		t.Fatalf("failed to create image stream %s\n", iSName)
	}
	defer f.Client.Delete(context.TODO(), stream)

	baselineImage = fmt.Sprintf("%s/%s:%s", otherNs, iSName, "latest")
	pb, err := f.CreateProfileBundle(pbName, baselineImage, framework.RhcosContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle %s: %s", pbName, err)
	}
	defer f.Client.Delete(context.TODO(), pb)

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("failed waiting for ProfileBundle to parse: %s", err)
	}
	if err := f.AssertMustHaveParsedProfiles(pbName, string(compv1alpha1.ScanTypeNode), "redhat_enterprise_linux_coreos_4"); err != nil {
		t.Fatalf("failed to assert profiles in ProfileBundle %s: %s", pbName, err)
	}

	// Check that the rule we removed exists in the original profile
	removedRuleName := prefixName(pbName, removedRule)
	err, found := f.DoesRuleExist(pb.Namespace, removedRuleName)
	if err != nil {
		t.Fatal(err)
	} else if !found {
		t.Fatalf("expected rule %s to exist", removedRuleName)
	}

	// Check that the rule we unlined in the modified profile is linked in the original
	profilePreUpdate := &compv1alpha1.Profile{}
	profileName := prefixName(pbName, moderateProfileName)
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: pb.Namespace, Name: profileName}, profilePreUpdate); err != nil {
		t.Fatalf("failed to get profile %s: %s", profileName, err)
	}
	unlinkedRuleName := prefixName(pbName, unlinkedRule)
	found = framework.IsRuleInProfile(unlinkedRuleName, profilePreUpdate)
	if !found {
		t.Fatalf("expected to find rule %s in profile %s", unlinkedRuleName, profileName)
	}

	// Update the reference in the image stream
	if err := f.UpdateImageStreamTag(iSName, modifiedImage, otherNs); err != nil {
		t.Fatalf("failed to update image stream %s: %s", iSName, err)
	}

	modifiedImageDigest, err := f.GetImageStreamUpdatedDigest(iSName, otherNs)
	if err != nil {
		t.Fatalf("failed to get digest for image stream %s: %s", iSName, err)
	}

	// Note that when an update happens through an imagestream tag, the operator doesn't get
	// a notification about it... It all happens on the Kube Deployment's side.
	// So we don't need to wait for the profile bundle's statuses
	if err := f.WaitForDeploymentContentUpdate(pbName, modifiedImageDigest); err != nil {
		t.Fatalf("failed waiting for content to update: %s", err)
	}

	if err := f.AssertProfileBundleMustHaveParsedRules(pbName); err != nil {
		t.Fatal(err)
	}
	// We removed this rule in the update, it must no longer exist
	err, found = f.DoesRuleExist(pb.Namespace, removedRuleName)
	if err != nil {
		t.Fatal(err)
	} else if found {
		t.Fatalf("rule %s unexpectedly found", removedRuleName)
	}

	// This rule was unlinked
	profilePostUpdate := &compv1alpha1.Profile{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: pb.Namespace, Name: profileName}, profilePostUpdate); err != nil {
		t.Fatalf("failed to get profile %s", profileName)
	}
	found = framework.IsRuleInProfile(unlinkedRuleName, profilePostUpdate)
	if found {
		t.Fatalf("rule %s unexpectedly found", unlinkedRuleName)
	}

}

func TestInvalidBundleWithUnexistentRef(t *testing.T) {
	t.Parallel()
	f := framework.Global
	const (
		unexistentImage = "bad-namespace/bad-image:latest"
	)

	pbName := framework.GetObjNameFromTest(t)
	pb, err := f.CreateProfileBundle(pbName, unexistentImage, framework.RhcosContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle %s: %s", pbName, err)
	}
	defer f.Client.Delete(context.TODO(), pb)

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamInvalid); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidBundleWithNoTag(t *testing.T) {
	t.Parallel()
	f := framework.Global
	const (
		noTagImage = "bad-namespace/bad-image"
	)

	pbName := framework.GetObjNameFromTest(t)

	pb, err := f.CreateProfileBundle(pbName, noTagImage, framework.RhcosContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle %s: %s", pbName, err)
	}
	defer f.Client.Delete(context.TODO(), pb)

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamInvalid); err != nil {
		t.Fatal(err)
	}
}

func TestServiceMonitoringMetricsTarget(t *testing.T) {
	t.Parallel()
	f := framework.Global

	err := f.SetupRBACForMetricsTest()
	if err != nil {
		t.Fatalf("failed to create service account: %s", err)
	}
	defer f.CleanUpRBACForMetricsTest()

	metricsTargets, err := f.WaitForPrometheusMetricTargets()
	if err != nil {
		t.Fatalf("failed to get prometheus metric targets: %s", err)
	}

	expectedMetricsCount := 2

	err = f.AssertServiceMonitoringMetricsTarget(metricsTargets, expectedMetricsCount)
	if err != nil {
		t.Fatalf("failed to assert metrics target: %s", err)
	}
}

func TestParsingErrorRestartsParserInitContainer(t *testing.T) {
	t.Parallel()
	f := framework.Global
	var (
		badImage  = fmt.Sprintf("%s:%s", brokenContentImagePath, "from")
		goodImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "to")
	)

	pbName := framework.GetObjNameFromTest(t)

	pb, err := f.CreateProfileBundle(pbName, badImage, framework.OcpContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle %s: %s", pbName, err)
	}
	defer f.Client.Delete(context.TODO(), pb)

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamInvalid); err != nil {
		t.Fatal(err)
	}

	// list the pods with profilebundle=pbName
	var lastErr error
	timeouterr := wait.Poll(framework.RetryInterval, framework.Timeout, func() (bool, error) {
		podList := &corev1.PodList{}
		inNs := client.InNamespace(f.OperatorNamespace)
		withLabel := client.MatchingLabels{"profile-bundle": pbName}
		if lastErr := f.Client.List(context.TODO(), podList, inNs, withLabel); lastErr != nil {
			return false, lastErr
		}

		if len(podList.Items) != 1 {
			return false, fmt.Errorf("expected one parser pod, listed %d", len(podList.Items))
		}
		parserPod := &podList.Items[0]

		// check that pod's initContainerStatuses field with name=profileparser has restartCount > 0 and that
		// lastState.Terminated.ExitCode != 0. This way we'll know we're restarting the init container
		// and retrying the parsing
		for i := range parserPod.Status.InitContainerStatuses {
			ics := parserPod.Status.InitContainerStatuses[i]
			if ics.Name != "profileparser" {
				continue
			}
			if ics.RestartCount < 1 {
				log.Println("The profileparser did not restart (yet?)")
				return false, nil
			}

			// wait until we get the restarted state
			if ics.LastTerminationState.Terminated == nil {
				log.Println("The profileparser does not have terminating state")
				return false, nil
			}
			if ics.LastTerminationState.Terminated.ExitCode == 0 {
				return true, fmt.Errorf("profileparser finished unsuccessfully")
			}
		}

		return true, nil
	})

	if err := framework.ProcessErrorOrTimeout(lastErr, timeouterr, "waiting for ProfileBundle parser to restart"); err != nil {
		t.Fatal(err)
	}

	// Fix the image and wait for the profilebundle to be parsed OK
	getPb := &compv1alpha1.ProfileBundle{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: pbName, Namespace: f.OperatorNamespace}, getPb); err != nil {
		t.Fatalf("failed to get ProfileBundle %s: %s", pbName, err)
	}

	updatePb := getPb.DeepCopy()
	updatePb.Spec.ContentImage = goodImage
	if err := f.Client.Update(context.TODO(), updatePb); err != nil {
		t.Fatalf("failed to update ProfileBundle %s: %s", pbName, err)
	}

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}
}

func TestRulesAreClassifiedAppropriately(t *testing.T) {
	t.Parallel()
	f := framework.Global
	for _, expected := range []struct {
		RuleName  string
		CheckType string
	}{
		{
			"ocp4-configure-network-policies-namespaces",
			compv1alpha1.CheckTypePlatform,
		},
		{
			"ocp4-directory-access-var-log-kube-audit",
			compv1alpha1.CheckTypeNode,
		},
		{
			"ocp4-general-apply-scc",
			compv1alpha1.CheckTypeNone,
		},
		{
			"ocp4-kubelet-enable-protect-kernel-sysctl",
			compv1alpha1.CheckTypeNode,
		},
	} {
		targetRule := &compv1alpha1.Rule{}
		key := types.NamespacedName{
			Name:      expected.RuleName,
			Namespace: f.OperatorNamespace,
		}

		if err := f.Client.Get(context.TODO(), key, targetRule); err != nil {
			t.Fatalf("failed to get rule %s: %s", targetRule.Name, err)
		}

		if targetRule.CheckType != expected.CheckType {
			log.Printf("Expected rule '%s' to be of type '%s'. Instead was: '%s'",
				expected.RuleName, expected.CheckType, targetRule.CheckType)
		}
	}
}

func TestSingleScanSucceeds(t *testing.T) {
	t.Parallel()
	f := framework.Global

	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatalf("failed to create scan %s: %s", scanName, err)
	}
	defer f.Client.Delete(context.TODO(), testScan)

	// Verify scanner container security capabilities during running phase
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}

	// Assert scanner container has correct capabilities (drops all, only has CAP_SYS_CHROOT)
	pods, err := f.GetPodsForScan(scanName)
	if err != nil {
		t.Fatal(err)
	}
	if len(pods) < 1 {
		t.Fatal("No scanner pods found for the scan")
	}

	// Find the scanner container and verify its capabilities
	found := false
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			if container.Name == "scanner" {
				found = true
				if container.SecurityContext == nil {
					t.Fatal("Scanner container has no security context")
				}
				if container.SecurityContext.Capabilities == nil {
					t.Fatal("Scanner container has no capabilities configuration")
				}

				// Verify privileged mode is false
				if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
					t.Fatal("Expected scanner container to run in non-privileged mode")
				}

				// Verify all capabilities are dropped
				droppedCaps := container.SecurityContext.Capabilities.Drop
				if len(droppedCaps) != 1 || string(droppedCaps[0]) != "ALL" {
					t.Fatalf("Expected scanner container to drop ALL capabilities, got: %v", droppedCaps)
				}

				// Verify CAP_SYS_CHROOT and CAP_SYS_ADMIN are added
				addedCaps := container.SecurityContext.Capabilities.Add
				if len(addedCaps) != 2 {
					t.Fatalf("Expected scanner container to have CAP_SYS_CHROOT and CAP_SYS_ADMIN capabilities, got: %v", addedCaps)
				}
				hasChroot := false
				hasSysAdmin := false
				for _, cap := range addedCaps {
					if string(cap) == "CAP_SYS_CHROOT" {
						hasChroot = true
					}
					if string(cap) == "CAP_SYS_ADMIN" {
						hasSysAdmin = true
					}
				}
				if !hasChroot || !hasSysAdmin {
					t.Fatalf("Expected scanner container to have both CAP_SYS_CHROOT and CAP_SYS_ADMIN capabilities, got: %v", addedCaps)
				}
				break
			}
		}
		if found {
			break
		}
	}

	if !found {
		t.Fatal("Scanner container not found in any pod")
	}

	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertScanIsCompliant(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	aggrString := fmt.Sprintf("compliance_operator_compliance_scan_status_total{name=\"%s\",phase=\"AGGREGATING\",result=\"NOT-AVAILABLE\"}", scanName)
	metricsSet := map[string]int{
		fmt.Sprintf("compliance_operator_compliance_scan_status_total{name=\"%s\",phase=\"DONE\",result=\"COMPLIANT\"}", scanName):          1,
		fmt.Sprintf("compliance_operator_compliance_scan_status_total{name=\"%s\",phase=\"LAUNCHING\",result=\"NOT-AVAILABLE\"}", scanName): 1,
		fmt.Sprintf("compliance_operator_compliance_scan_status_total{name=\"%s\",phase=\"PENDING\",result=\"\"}", scanName):                1,
		fmt.Sprintf("compliance_operator_compliance_scan_status_total{name=\"%s\",phase=\"RUNNING\",result=\"NOT-AVAILABLE\"}", scanName):   1,
	}

	var metErr error
	// Aggregating may be variable, could be registered 1 to 3 times.
	for i := 1; i < 4; i++ {
		metricsSet[aggrString] = i
		err = framework.AssertEachMetric(f.OperatorNamespace, metricsSet)
		if err == nil {
			metErr = nil
			break
		}
		metErr = err
	}

	if metErr != nil {
		t.Fatalf("failed to assert metrics for scan %s: %s\n", scanName, metErr)
	}

	err = f.AssertScanHasValidPVCReference(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatalf("failed to assert PVC reference for scan %s: %s", scanName, err)
	}

	// Validate exit-code is "0"
	exitCode, _, err := f.GetScanExitCodeAndErrorMsg(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
	expectedExitCode := "0"
	if exitCode != expectedExitCode {
		t.Fatalf("Expected ConfigMap exit-code to be '%s', but got: '%s'", expectedExitCode, exitCode)
	}
}

func TestSingleScanTimestamps(t *testing.T) {
	t.Parallel()
	f := framework.Global

	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatalf("failed to create scan %s: %s", scanName, err)
	}
	defer f.Client.Delete(context.TODO(), testScan)

	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	// assertComplianceCheckResultTimestamps checks that the timestamps are set
	// and that they are set to the same value of startTimestamp of the scan
	err = f.AssertComplianceCheckResultTimestamps(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	// rerun the scan
	err = f.ReRunScan(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	// assertComplianceCheckResultTimestamps checks that the timestamps are set
	// and that they are set to the same value of startTimestamp of the scan
	err = f.AssertComplianceCheckResultTimestamps(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

}

func TestNonExistentDeprecatedProfile(t *testing.T) {
	t.Parallel()
	f := framework.Global

	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_non_existing_profile",
			Content:      framework.OcpContentFile,
			ContentImage: contentImagePath,
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatalf("failed to create scan %s: %s", scanName, err)
	}
	defer f.Client.Delete(context.TODO(), testScan)

	// The profile deprecation warning is sent out during Pending phase
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertScanIsInError(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	if err = f.Client.Get(context.TODO(), types.NamespacedName{Name: scanName, Namespace: f.OperatorNamespace}, testScan); err != nil {
		t.Fatal(err)
	}
	if testScan.Status.ErrorMessage != "Could not check whether the Profile used by ComplianceScan is deprecated" {
		t.Fatal(errors.New("expected error message to be from failed profile deprecation check"))
	}
}

func TestScanProducesRemediationsAndLabels(t *testing.T) {
	t.Parallel()
	f := framework.Global
	bindingName := framework.GetObjNameFromTest(t)
	tpName := framework.GetObjNameFromTest(t)

	// When using a profile directly, the profile name gets re-used
	// in the scan. By using a tailored profile we ensure that
	// the scan is unique and we get no clashes.
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       t.Name(),
			Description: t.Name(),
			Extends:     "ocp4-e8",
		},
	}

	createTPErr := f.Client.Create(context.TODO(), tp, nil)
	if createTPErr != nil {
		t.Fatal(createTPErr)
	}
	defer f.Client.Delete(context.TODO(), tp)
	scanSettingBinding := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     tpName,
				Kind:     "TailoredProfile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			Name:     "default",
			Kind:     "ScanSetting",
			APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), &scanSettingBinding, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSettingBinding)
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	// Since the scan was not compliant, there should be some remediations and none
	// of them should be an error
	inNs := client.InNamespace(f.OperatorNamespace)
	withLabel := client.MatchingLabels{compv1alpha1.SuiteLabel: bindingName}
	fmt.Println(inNs, withLabel)
	remList := &compv1alpha1.ComplianceRemediationList{}
	err = f.Client.List(context.TODO(), remList, inNs, withLabel)
	if err != nil {
		t.Fatal(err)
	}

	if len(remList.Items) == 0 {
		t.Fatal("expected at least one remediation")
	}
	for _, rem := range remList.Items {
		if rem.Status.ApplicationState != compv1alpha1.RemediationNotApplied {
			t.Fatal("expected all remediations are unapplied when scan finishes")
		}
	}
	// Verify ComplianceCheckResult labels are correctly set
	// Get all checks from the suite to verify label functionality
	checkList := &compv1alpha1.ComplianceCheckResultList{}
	err = f.Client.List(context.TODO(), checkList, inNs, withLabel)
	if err != nil {
		t.Fatal(err)
	}
	if len(checkList.Items) == 0 {
		t.Fatal("expected at least one check result")
	}
	// Verify all required labels are present on every check result
	// For some labels we can verify the exact value
	labelsWithValues := map[string]string{
		compv1alpha1.SuiteLabel:          bindingName,
		compv1alpha1.ComplianceScanLabel: bindingName,
	}
	// For other labels we just verify they are present (non-empty)
	labelsPresenceOnly := []string{
		compv1alpha1.ComplianceCheckResultSeverityLabel,
		compv1alpha1.ComplianceCheckResultStatusLabel,
	}
	for _, check := range checkList.Items {
		// Check labels with specific expected values
		for label, expected := range labelsWithValues {
			if check.Labels[label] != expected {
				t.Fatalf("check %s label %s: got %q, want %q", check.Name, label, check.Labels[label], expected)
			}
		}
		// Check labels that must be present (non-empty)
		for _, label := range labelsPresenceOnly {
			if check.Labels[label] == "" {
				t.Fatalf("check %s is missing label %s", check.Name, label)
			}
		}
	}
}

func TestSingleScanWithStorageSucceeds(t *testing.T) {
	t.Parallel()
	f := framework.Global
	scanName := framework.GetObjNameFromTest(t)
	t.Logf("Creating ComplianceScan %s with storage size 2Gi", scanName)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				RawResultStorage: compv1alpha1.RawResultStorageSettings{
					Size: "2Gi",
				},
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testScan)
	t.Logf("Waiting for scan %s to reach phase Done", scanName)
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatalf("Scan %s did not reach Done phase: %v", scanName, err)
	}
	t.Logf("Scan %s reached Done phase", scanName)

	t.Logf("Asserting scan %s is compliant", scanName)
	err = f.AssertScanIsCompliant(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatalf("Scan %s is not compliant: %v", scanName, err)
	}
	t.Logf("Asserting scan %s has valid PVC reference with size 2Gi", scanName)
	err = f.AssertScanHasValidPVCReferenceWithSize(scanName, "2Gi", f.OperatorNamespace)
	if err != nil {
		t.Fatalf("Scan %s PVC reference check failed: %v", scanName, err)
	}
	t.Logf("Asserting ARF report exists in PVC for scan %s", scanName)
	err = f.AssertARFReportExistsInPVC(t, scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatalf("Scan %s ARF report check failed: %v", scanName, err)
	}
	t.Logf("All assertions passed for scan %s", scanName)
}

func TestScanWithUnexistentResourceFails(t *testing.T) {
	// This tests scan behavior when Kubernetes resource doesn't exist
	// The data stream, content image and profile all exist
	t.Parallel()
	f := framework.Global
	pbName := framework.GetObjNameFromTest(t)
	var unexistentImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "unexistent_resource")
	origPb, err := f.CreateProfileBundle(pbName, unexistentImage, framework.UnexistentResourceContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle: %s", err)
	}
	// This should get cleaned up at the end of the test
	defer f.Client.Delete(context.TODO(), origPb)
	if err = f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("failed waiting for the ProfileBundle to become available: %s", err)
	}

	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_test",
			Content:      framework.UnexistentResourceContentFile,
			ContentImage: unexistentImage,
			Rule:         "xccdf_org.ssgproject.content_rule_api_server_unexistent_resource",
			ScanType:     compv1alpha1.ScanTypePlatform,
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err = f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertScanIsNonCompliant(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	if err = f.ScanHasWarnings(scanName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}

	// Validate exit-code is "2"
	exitCode, _, err := f.GetScanExitCodeAndErrorMsg(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
	expectedExitCode := "2"
	if exitCode != expectedExitCode {
		t.Fatalf("Expected ConfigMap exit-code to be '%s', but got: '%s'", expectedExitCode, exitCode)
	}
}

func TestScanStorageOutOfLimitRangeFails(t *testing.T) {
	t.Parallel()
	f := framework.Global
	// Create LimitRange
	lr := &corev1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pvc-limitrange",
			Namespace: f.OperatorNamespace,
		},
		Spec: corev1.LimitRangeSpec{
			Limits: []corev1.LimitRangeItem{
				{
					Type: corev1.LimitTypePersistentVolumeClaim,
					Max: corev1.ResourceList{
						corev1.ResourceStorage: resource.MustParse("5Gi"),
					},
				},
			},
		},
	}
	if err := f.Client.Create(context.TODO(), lr, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), lr)

	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				RawResultStorage: compv1alpha1.RawResultStorageSettings{
					Size: "6Gi",
				},
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testScan)
	f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	err = f.AssertScanIsInError(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

}

func TestSingleTailoredPlatformScanSucceedsOptionalProxy(t *testing.T) {
	t.Parallel()
	f := framework.Global

	// Check if cluster is proxy and verify deployment env vars if so
	var httpsProxy string
	proxy := &configv1.Proxy{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: "cluster"}, proxy); err == nil {
		httpsProxy = proxy.Spec.HTTPSProxy
		if httpsProxy != "" {
			deployment, err := f.KubeClient.AppsV1().Deployments(f.OperatorNamespace).Get(context.TODO(), "compliance-operator", metav1.GetOptions{})
			if err != nil {
				t.Fatalf("failed to get compliance-operator deployment: %s", err)
			}
			if len(deployment.Spec.Template.Spec.Containers) == 0 {
				t.Fatal("compliance-operator deployment has no containers")
			}

			envMap := make(map[string]string)
			for _, env := range deployment.Spec.Template.Spec.Containers[0].Env {
				if env.Name == "HTTPS_PROXY" {
					envMap[env.Name] = env.Value
				}
			}
			if httpsProxy != "" && envMap["HTTPS_PROXY"] != httpsProxy {
				t.Fatalf("HTTPS_PROXY mismatch. Expected: %s, Got: %s", httpsProxy, envMap["HTTPS_PROXY"])
			}
		}
	}

	tpName := "test-tailoredplatformprofile"
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "TestSingleTailoredPlatformScanSucceeds",
			Description: "TestSingleTailoredPlatformScanSucceeds",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-cluster-version-operator-exists",
					Rationale: "Test for platform profile tailoring",
				},
			},
		},
	}
	err := f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	err = f.WaitForTailoredProfileStatus(f.OperatorNamespace, tpName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatal(err)
	}

	suiteName := framework.GetObjNameFromTest(t)
	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     tpName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}
	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// When using SSB with TailoredProfile, the scan has same name as the TP
	scanName := tpName
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanIsCompliant(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	// If proxy cluster, verify httpsProxy in configmap
	// CO only propagates and uses httpsProxy
	if httpsProxy != "" {
		cm := &corev1.ConfigMap{}
		cmName := scanName + "-openscap-env-map"
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: cmName, Namespace: f.OperatorNamespace}, cm); err != nil && apierrors.IsNotFound(err) {
			cmList := &corev1.ConfigMapList{}
			if err := f.Client.List(context.TODO(), cmList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels{
				compv1alpha1.ComplianceScanLabel: scanName,
				compv1alpha1.ScriptLabel:         "",
			}); err != nil {
				t.Fatalf("failed to list ConfigMaps: %s", err)
			}
			for i := range cmList.Items {
				if strings.Contains(cmList.Items[i].Name, "openscap-env-map") && cmList.Items[i].Data["HTTPS_PROXY"] != "" {
					cm = &cmList.Items[i]
					break
				}
			}
		} else if err != nil {
			t.Fatalf("failed to get ConfigMap: %s", err)
		}

		if cm.Data["HTTPS_PROXY"] != httpsProxy {
			t.Fatalf("HTTPS_PROXY mismatch in configmap. Expected: %s, Got: %s", httpsProxy, cm.Data["HTTPS_PROXY"])
		}
	}
}

func TestScanWithNodeSelectorFiltersCorrectly(t *testing.T) {
	t.Parallel()
	f := framework.Global
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}
	testComplianceScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-filtered-scan",
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			NodeSelector: selectWorkers,
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testComplianceScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testComplianceScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, "test-filtered-scan", compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	nodes, err := f.GetNodesWithSelector(selectWorkers)
	if err != nil {
		t.Fatal(err)
	}
	configmaps, err := f.GetConfigMapsFromScan(testComplianceScan)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertNodeNameIsInTargetAndFactIdentifierInCM(nodes, configmaps)
	if err != nil {
		t.Fatal(err)
	}

	if len(nodes) != len(configmaps) {
		t.Fatalf("The number of reports doesn't match the number of selected nodes: %d reports / %d nodes", len(configmaps), len(nodes))
	}
	err = f.AssertScanIsCompliant("test-filtered-scan", f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScanWithNodeSelectorNoMatches(t *testing.T) {
	t.Parallel()
	f := framework.Global
	scanName := framework.GetObjNameFromTest(t)
	selectNone := map[string]string{
		"node-role.kubernetes.io/no-matches": "",
	}
	testComplianceScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			NodeSelector: selectNone,
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug:             true,
				ShowNotApplicable: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testComplianceScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testComplianceScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanIsNotApplicable(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScanWithInvalidScanTypeFails(t *testing.T) {
	t.Parallel()
	f := framework.Global
	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      "ssg-ocp4-non-existent.xml",
			ContentImage: contentImagePath,
			ScanType:     "BadScanType",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanIsInError(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScanWithInvalidContentFails(t *testing.T) {
	// This test logs a "Could not get Profile" error, but that is expected
	t.Parallel()
	f := framework.Global
	scanName := "test-scan-w-invalid-content"
	exampleComplianceScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      "ssg-ocp4-non-existent.xml",
			ContentImage: contentImagePath,
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), exampleComplianceScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), exampleComplianceScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanIsInError(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScanWithInvalidProfileFails(t *testing.T) {
	t.Parallel()
	f := framework.Global
	scanName := "test-scan-w-invalid-profile"
	exampleComplianceScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_coreos-unexistent",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), exampleComplianceScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), exampleComplianceScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanIsInError(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestMalformedTailoredScanFails(t *testing.T) {
	t.Parallel()
	f := framework.Global
	cmName := "test-malformed-tailored-scan-fails-cm"
	tailoringCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: f.OperatorNamespace,
		},
		// The tailored profile's namespace is wrong. It should be xccdf-1.2, but it was
		// declared as xccdf. So it should report an error
		Data: map[string]string{
			"tailoring.xml": `<?xml version="1.0" encoding="UTF-8"?>
<xccdf-1.2:Tailoring xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" id="xccdf_compliance.openshift.io_tailoring_test-tailoredprofile">
<xccdf-1.2:benchmark href="/content/ssg-rhcos4-ds.xml"></xccdf-1.2:benchmark>
<xccdf-1.2:version time="2020-04-28T07:04:13Z">1</xccdf-1.2:version>
<xccdf-1.2:Profile id="xccdf_compliance.openshift.io_profile_test-tailoredprofile">
<xccdf-1.2:title>Test Tailored Profile</xccdf-1.2:title>
<xccdf-1.2:description>Test Tailored Profile</xccdf-1.2:description>
<xccdf-1.2:select idref="xccdf_org.ssgproject.content_rule_no_netrc_files" selected="true"></xccdf-1.2:select>
</xccdf-1.2:Profile>
</xccdf-1.2:Tailoring>`,
		},
	}

	err := f.Client.Create(context.TODO(), tailoringCM, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tailoringCM)

	scanName := "test-malformed-tailored-scan-fails"
	exampleComplianceScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_compliance.openshift.io_profile_test-tailoredprofile",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
			TailoringConfigMap: &compv1alpha1.TailoringConfigMapRef{
				Name: tailoringCM.Name,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err = f.Client.Create(context.TODO(), exampleComplianceScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), exampleComplianceScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanIsInError(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScanWithEmptyTailoringCMNameFails(t *testing.T) {
	t.Parallel()
	f := framework.Global
	scanName := "test-scan-w-empty-tailoring-cm"
	exampleComplianceScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			TailoringConfigMap: &compv1alpha1.TailoringConfigMapRef{
				Name: "",
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), exampleComplianceScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), exampleComplianceScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertScanIsInError(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScanWithMissingTailoringCMFailsAndRecovers(t *testing.T) {
	t.Parallel()
	f := framework.Global
	scanName := "test-scan-w-missing-tailoring-cm"

	tpName := "test-tailoredprofile-missing-cm"
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "TestScanWithMissingTailoringCMFailsAndRecovers",
			Description: "TestScanWithMissingTailoringCMFailsAndRecovers",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "rhcos4-no-netrc-files",
					Rationale: "Test for platform profile tailoring missing CM fails and recovers",
				},
			},
		},
	}
	createTPErr := f.Client.Create(context.TODO(), tp, nil)
	if createTPErr != nil {
		t.Fatal(createTPErr)
	}
	defer f.Client.Delete(context.TODO(), tp)

	exampleComplianceScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_compliance.openshift.io_profile_test-tailoredprofile-missing-cm",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
			TailoringConfigMap: &compv1alpha1.TailoringConfigMapRef{
				Name: "missing-tailoring-file",
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), exampleComplianceScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), exampleComplianceScan)

	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseLaunching)
	if err != nil {
		t.Fatal(err)
	}

	var resultErr error
	// The status might still be NOT-AVAILABLE... we can wait a bit
	// for the reconciliation to update it.
	_ = wait.PollImmediate(framework.RetryInterval, framework.Timeout, func() (bool, error) {
		if resultErr = f.AssertScanIsInError(scanName, f.OperatorNamespace); resultErr != nil {
			return false, nil
		}
		return true, nil
	})
	if resultErr != nil {
		t.Fatalf("failed waiting for the config map: %s", resultErr)
	}

	tailoringCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "missing-tailoring-file",
			Namespace: f.OperatorNamespace,
		},
		Data: map[string]string{
			"tailoring.xml": `<?xml version="1.0" encoding="UTF-8"?>
<xccdf-1.2:Tailoring xmlns:xccdf-1.2="http://checklists.nist.gov/xccdf/1.2" id="xccdf_compliance.openshift.io_tailoring_test-tailoredprofile-missing-cm">
<xccdf-1.2:benchmark href="/content/ssg-rhcos4-ds.xml"></xccdf-1.2:benchmark>
<xccdf-1.2:version time="2020-04-28T07:04:13Z">1</xccdf-1.2:version>
<xccdf-1.2:Profile id="xccdf_compliance.openshift.io_profile_test-tailoredprofile-missing-cm">
<xccdf-1.2:title>Test Tailored Profile</xccdf-1.2:title>
<xccdf-1.2:description>Test Tailored Profile</xccdf-1.2:description>
<xccdf-1.2:select idref="xccdf_org.ssgproject.content_rule_no_netrc_files" selected="true"></xccdf-1.2:select>
</xccdf-1.2:Profile>
</xccdf-1.2:Tailoring>`,
		},
	}
	err = f.Client.Create(context.TODO(), tailoringCM, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tailoringCM)

	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanIsCompliant(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestMissingPodInRunningState(t *testing.T) {
	t.Parallel()
	f := framework.Global
	scanName := "test-missing-pod-scan"
	exampleComplianceScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), exampleComplianceScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), exampleComplianceScan)

	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}
	pods, err := f.GetPodsForScan(scanName)
	if err != nil {
		t.Fatal(err)
	}
	if len(pods) < 1 {
		t.Fatal("No pods gotten from query for the scan")
	}
	podToDelete := pods[rand.Intn(len(pods))]
	// Delete pod ASAP
	zeroSeconds := int64(0)
	do := client.DeleteOptions{GracePeriodSeconds: &zeroSeconds}
	err = f.Client.Delete(context.TODO(), &podToDelete, &do)
	if err != nil {
		t.Fatal(err)
	}
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertScanIsCompliant(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSuiteWithInvalidScheduleShowsError(t *testing.T) {
	t.Parallel()
	f := framework.Global
	suiteName := "test-suite-with-invalid-schedule"
	testSuite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: false,
				Schedule:              "This is WRONG",
			},
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					Name: fmt.Sprintf("%s-workers-scan", suiteName),
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
						},
						NodeSelector: map[string]string{
							"node-role.kubernetes.io/worker": "",
						},
					},
				},
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultError)
	if err != nil {
		t.Fatal(err)
	}
	err = f.SuiteErrorMessageMatchesRegex(f.OperatorNamespace, suiteName, "Suite was invalid: .*")
	if err != nil {
		t.Fatal(err)
	}
}

func TestScheduledSuite(t *testing.T) {
	t.Parallel()
	f := framework.Global
	suiteName := "test-scheduled-suite"

	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}

	testSuite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: false,
				Schedule:              "*/2 * * * *",
			},
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					Name: workerScanName,
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							RawResultStorage: compv1alpha1.RawResultStorageSettings{
								Rotation: 1,
							},
							Debug: true,
						},
					},
				},
			},
		},
	}

	err := f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for one re-scan
	err = f.WaitForReScanStatus(f.OperatorNamespace, workerScanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for a second one to assert this is running scheduled as expected
	err = f.WaitForReScanStatus(f.OperatorNamespace, workerScanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	// Remove cronjob so it doesn't keep running while other tests are
	// running. Use Patch instead of Update to avoid resource version
	// conflicts with the controller.
	patch := []byte(`{"spec":{"schedule":""}}`)
	if err = f.Client.Patch(context.TODO(), testSuite, client.RawPatch(types.MergePatchType, patch)); err != nil {
		t.Fatal(err)
	}

	rawResultClaimName, err := f.GetRawResultClaimNameFromScan(f.OperatorNamespace, workerScanName)
	if err != nil {
		t.Fatal(err)
	}

	rotationCheckerPod := framework.GetRotationCheckerWorkload(f.OperatorNamespace, rawResultClaimName)
	if err = f.Client.Create(context.TODO(), rotationCheckerPod, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), rotationCheckerPod)

	err = f.AssertResultStorageHasExpectedItemsAfterRotation(1, f.OperatorNamespace, rotationCheckerPod.Name)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScheduledSuitePriorityClass(t *testing.T) {
	t.Parallel()
	f := framework.Global
	suiteName := "test-scheduled-suite-priority-class"
	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}

	priorityClass := &schedulingv1.PriorityClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-compliance-suite-high-priority",
		},
		Value: 100,
	}

	// Ensure that the priority class is created
	err := f.Client.Create(context.TODO(), priorityClass, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), priorityClass)

	testSuite := &compv1alpha1.ComplianceSuite{
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
					Name: workerScanName,
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							PriorityClass: "e2e-compliance-suite-high-priority",
							RawResultStorage: compv1alpha1.RawResultStorageSettings{
								Rotation: 1,
							},
							Debug: true,
						},
					},
				},
			},
		},
	}

	err = f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	podList := &corev1.PodList{}
	err = f.Client.List(context.TODO(), podList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels(map[string]string{
		"workload": "scanner",
	}))
	if err != nil {
		t.Fatal(err)
	}
	// check if the scanning pod has properly been created and has priority class set
	for _, pod := range podList.Items {
		if strings.Contains(pod.Name, workerScanName) {
			if err := framework.WaitForPod(framework.CheckPodPriorityClass(f.KubeClient, pod.Name, f.OperatorNamespace, "e2e-compliance-suite-high-priority")); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScheduledSuiteNoStorage(t *testing.T) {
	t.Parallel()
	f := framework.Global
	suiteName := "test-scheduled-suite-no-storage"
	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}

	falseValue := false
	testSuite := &compv1alpha1.ComplianceSuite{
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
					Name: workerScanName,
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							RawResultStorage: compv1alpha1.RawResultStorageSettings{
								Enabled: &falseValue,
							},
							Debug: true,
						},
					},
				},
			},
		},
	}

	err := f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	// Ensure that all the scans in the suite have finished and are marked as Done.
	// Accept any result since this test validates storage behavior, not compliance outcome.
	err = f.WaitForSuiteScansStatusAnyResult(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone,
		compv1alpha1.ResultCompliant, compv1alpha1.ResultNonCompliant, compv1alpha1.ResultError)
	if err != nil {
		t.Fatal(err)
	}

	pvcList := &corev1.PersistentVolumeClaimList{}
	err = f.Client.List(context.TODO(), pvcList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels(map[string]string{
		compv1alpha1.ComplianceScanLabel: workerScanName,
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, pvc := range pvcList.Items {
		t.Fatalf("Found unexpected PVC %s", pvc.Name)
	}
}

func TestScheduledSuitePlatformNoStorage(t *testing.T) {
	t.Parallel()
	f := framework.Global
	suiteName := "test-scheduled-suite-platform-no-storage"
	platformScanName := fmt.Sprintf("%s-platform-scan", suiteName)

	falseValue := false
	testSuite := &compv1alpha1.ComplianceSuite{
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
					Name: platformScanName,
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.OcpContentFile,
						Rule:         "xccdf_org.ssgproject.content_rule_ocp_idp_no_htpasswd",
						ScanType:     compv1alpha1.ScanTypePlatform,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							RawResultStorage: compv1alpha1.RawResultStorageSettings{
								Enabled: &falseValue,
							},
							Debug: true,
						},
					},
				},
			},
		},
	}

	err := f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}

	pvcList := &corev1.PersistentVolumeClaimList{}
	err = f.Client.List(context.TODO(), pvcList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels(map[string]string{
		compv1alpha1.ComplianceScanLabel: platformScanName,
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, pvc := range pvcList.Items {
		t.Fatalf("Found unexpected PVC %s", pvc.Name)
	}
}

func TestScheduledSuiteInvalidPriorityClass(t *testing.T) {
	t.Parallel()
	f := framework.Global
	suiteName := "test-scheduled-suite-invalid-priority-class"

	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}

	testSuite := &compv1alpha1.ComplianceSuite{
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
					Name: workerScanName,
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							PriorityClass: "priority-invalid",
							RawResultStorage: compv1alpha1.RawResultStorageSettings{
								Rotation: 1,
							},
							Debug: true,
						},
					},
				},
			},
		},
	}

	err := f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	podList := &corev1.PodList{}
	err = f.Client.List(context.TODO(), podList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels(map[string]string{
		"workload": "scanner",
	}))
	if err != nil {
		t.Fatal(err)
	}
	// check if the scanning pod has properly been created and has priority class set
	for _, pod := range podList.Items {
		if strings.Contains(pod.Name, workerScanName) {
			if err := framework.WaitForPod(framework.CheckPodPriorityClass(f.KubeClient, pod.Name, f.OperatorNamespace, "")); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScheduledSuiteUpdate(t *testing.T) {
	t.Parallel()
	f := framework.Global
	suiteName := framework.GetObjNameFromTest(t)
	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}

	initialSchedule := "0 * * * *"
	testSuite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: false,
				Schedule:              initialSchedule,
			},
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					Name: workerScanName,
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
						},
					},
				},
			},
		},
	}

	err := f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}

	err = f.WaitForCronJobWithSchedule(f.OperatorNamespace, suiteName, initialSchedule)
	if err != nil {
		t.Fatal(err)
	}

	// Get new reference of suite
	foundSuite := &compv1alpha1.ComplianceSuite{}
	key := types.NamespacedName{Name: testSuite.Name, Namespace: testSuite.Namespace}
	if err = f.Client.Get(context.TODO(), key, foundSuite); err != nil {
		t.Fatal(err)
	}

	// Update schedule
	testSuiteCopy := foundSuite.DeepCopy()
	updatedSchedule := "*/2 * * * *"
	testSuiteCopy.Spec.Schedule = updatedSchedule
	if err = f.Client.Update(context.TODO(), testSuiteCopy); err != nil {
		t.Fatal(err)
	}

	if err = f.WaitForCronJobWithSchedule(f.OperatorNamespace, suiteName, updatedSchedule); err != nil {
		t.Fatal(err)
	}

	// Clean up
	// Get new reference of suite
	foundSuite = &compv1alpha1.ComplianceSuite{}
	if err = f.Client.Get(context.TODO(), key, foundSuite); err != nil {
		t.Fatal(err)
	}

	// Remove cronjob so it doesn't keep running while other tests are running
	testSuiteCopy = foundSuite.DeepCopy()
	updatedSchedule = ""
	testSuiteCopy.Spec.Schedule = updatedSchedule
	if err = f.Client.Update(context.TODO(), testSuiteCopy); err != nil {
		t.Fatal(err)
	}
}

// TestCustomRuleTailoredProfile tests CustomRule functionality with TailoredProfiles
func TestCustomRuleMetadataPropagation(t *testing.T) {
	t.Parallel()
	f := framework.Global

	testName := framework.GetObjNameFromTest(t)
	customRuleName := fmt.Sprintf("%s-meta-rule", testName)
	tpName := fmt.Sprintf("%s-tp", testName)
	ssbName := fmt.Sprintf("%s-ssb", testName)
	testNamespace := f.OperatorNamespace

	customLabels := map[string]string{
		"business-unit": "payments",
		"risk-tier":     "critical",
	}
	customAnnotations := map[string]string{
		"internal-id":   "SEC-4021",
		"audit-contact": "platform-security-team",
	}

	customRule := &compv1alpha1.CustomRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:        customRuleName,
			Namespace:   testNamespace,
			Labels:      customLabels,
			Annotations: customAnnotations,
		},
		Spec: compv1alpha1.CustomRuleSpec{
			RulePayload: compv1alpha1.RulePayload{
				ID:            customRuleName,
				Title:         "Metadata Propagation Test Rule",
				Description:   "A rule that always passes, used to verify custom metadata propagation",
				Severity:      "medium",
				ScannerType:   compv1alpha1.ScannerTypeCEL,
				Expression:    "namespaces.items.size() > 0",
				FailureReason: "This rule should always pass",
				Inputs: []compv1alpha1.InputPayload{
					{
						Name: "namespaces",
						KubernetesInputSpec: compv1alpha1.KubernetesInputSpec{
							APIVersion: "v1",
							Resource:   "namespaces",
						},
					},
				},
			},
		},
	}

	err := f.Client.Create(context.TODO(), customRule, nil)
	if err != nil {
		t.Fatalf("Failed to create CustomRule: %v", err)
	}
	defer f.Client.Delete(context.TODO(), customRule)

	err = f.WaitForCustomRuleStatus(testNamespace, customRuleName, "Ready")
	if err != nil {
		t.Fatalf("CustomRule validation failed: %v", err)
	}

	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: testNamespace,
			Annotations: map[string]string{
				compv1alpha1.DisableOutdatedReferenceValidation: "true",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "Metadata Propagation Test Profile",
			Description: "Tests that custom labels and annotations propagate to ComplianceCheckResults",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      customRuleName,
					Kind:      "CustomRule",
					Rationale: "Verify metadata propagation",
				},
			},
		},
	}

	err = f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatalf("Failed to create TailoredProfile: %v", err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ssbName,
			Namespace: testNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     tpName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}

	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatalf("Failed to create ScanSettingBinding: %v", err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	suiteName := ssbName
	err = f.WaitForSuiteScansStatus(testNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatalf("Scan did not complete as expected: %v", err)
	}

	scanName := tpName
	expectedCheck := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", scanName, customRuleName),
			Namespace: testNamespace,
		},
		ID:     customRuleName,
		Status: compv1alpha1.CheckResultPass,
	}

	err = f.AssertHasCheck(suiteName, scanName, expectedCheck)
	if err != nil {
		t.Fatalf("Check result assertion failed: %v", err)
	}

	var checkResult compv1alpha1.ComplianceCheckResult
	err = f.Client.Get(context.TODO(), types.NamespacedName{
		Name:      expectedCheck.Name,
		Namespace: testNamespace,
	}, &checkResult)
	if err != nil {
		t.Fatalf("Failed to get ComplianceCheckResult: %v", err)
	}

	for k, v := range customLabels {
		if checkResult.Labels[k] != v {
			t.Errorf("expected label %s=%s, got %q", k, v, checkResult.Labels[k])
		}
	}
	for k, v := range customAnnotations {
		if checkResult.Annotations[k] != v {
			t.Errorf("expected annotation %s=%s, got %q", k, v, checkResult.Annotations[k])
		}
	}

	if checkResult.Labels[compv1alpha1.ComplianceScanLabel] != scanName {
		t.Errorf("operator-managed scan label should not be overridden, got %q", checkResult.Labels[compv1alpha1.ComplianceScanLabel])
	}
	if checkResult.Labels[compv1alpha1.ComplianceCheckResultStatusLabel] != string(compv1alpha1.CheckResultPass) {
		t.Errorf("operator-managed status label should not be overridden, got %q", checkResult.Labels[compv1alpha1.ComplianceCheckResultStatusLabel])
	}
}

func TestTailoredProfileRejectsMixedRuleTypes(t *testing.T) {
	t.Parallel()
	f := framework.Global

	testName := framework.GetObjNameFromTest(t)
	testNamespace := f.OperatorNamespace
	customRuleName := fmt.Sprintf("%s-custom", testName)
	tpName := fmt.Sprintf("%s-tp-mixed", testName)
	expression := `pods.items.all(pod, pod.spec.containers.all(container, !has(container.securityContext) || !has(container.securityContext.privileged) || container.securityContext.privileged == false ))`
	// Step 1: Create a valid CustomRule
	customRule := &compv1alpha1.CustomRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      customRuleName,
			Namespace: testNamespace,
		},
		Spec: compv1alpha1.CustomRuleSpec{
			RulePayload: compv1alpha1.RulePayload{
				ID:          customRuleName,
				Title:       "No Privileged Containers",
				Description: "Ensures no containers are running in privileged mode",
				Severity:    "high",
				ScannerType: compv1alpha1.ScannerTypeCEL,
				Expression:  expression,
				Inputs: []compv1alpha1.InputPayload{
					{
						Name: "pods",
						KubernetesInputSpec: compv1alpha1.KubernetesInputSpec{
							APIVersion: "v1",
							Resource:   "pods",
						},
					},
				},
				FailureReason: "Privileged container(s) found",
			},
		},
	}

	err := f.Client.Create(context.TODO(), customRule, nil)
	if err != nil {
		t.Fatalf("Failed to create CustomRule: %v", err)
	}
	defer f.Client.Delete(context.TODO(), customRule)

	// Wait for CustomRule to be validated and ready
	err = f.WaitForCustomRuleStatus(testNamespace, customRuleName, "Ready")
	if err != nil {
		t.Fatalf("CustomRule validation failed: %v", err)
	}
	t.Logf("CustomRule %s is ready", customRuleName)

	// Step 2: Create TailoredProfile that mixes CustomRules and regular Rules
	// This should fail validation
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: testNamespace,
			Annotations: map[string]string{
				compv1alpha1.DisableOutdatedReferenceValidation: "true",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "Mixed Rule Types Test",
			Description: "This profile incorrectly mixes CustomRules and regular Rules",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					// CustomRule - CEL-based
					Name:      customRuleName,
					Kind:      "CustomRule",
					Rationale: "Ensure containers are not privileged",
				},
				{
					// Regular Rule - OpenSCAP-based
					Name:      "ocp4-cluster-version-operator-exists",
					Kind:      "Rule",
					Rationale: "Make sure cluster version operator exists",
				},
			},
		},
	}

	err = f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatalf("Failed to create TailoredProfile: %v", err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	// Step 3: Wait for TailoredProfile to be in Error state
	err = f.WaitForTailoredProfileStatus(testNamespace, tpName, compv1alpha1.TailoredProfileStateError)
	if err != nil {
		t.Fatalf("TailoredProfile did not enter Error state: %v", err)
	}
	t.Logf("TailoredProfile %s is in Error state as expected", tpName)

	// Step 4: Verify the error message
	tpWithError := &compv1alpha1.TailoredProfile{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: tpName, Namespace: testNamespace}, tpWithError)
	if err != nil {
		t.Fatalf("Failed to get TailoredProfile: %v", err)
	}

	expectedErrorContent := "cannot mix CEL rules (CustomRules) with OpenSCAP Rules"
	if !strings.Contains(tpWithError.Status.ErrorMessage, expectedErrorContent) {
		t.Fatalf("Expected error message to contain '%s', but got: %s", expectedErrorContent, tpWithError.Status.ErrorMessage)
	}
	t.Logf("Error message correctly indicates mixed rule types: %s", tpWithError.Status.ErrorMessage)

	// Step 5: Create a TailoredProfile with only CustomRules (should work)
	tpValidName := fmt.Sprintf("%s-tp-valid", testName)
	tpValid := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpValidName,
			Namespace: testNamespace,
			Annotations: map[string]string{
				compv1alpha1.DisableOutdatedReferenceValidation: "true",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "CustomRules Only Test",
			Description: "This profile correctly uses only CustomRules",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      customRuleName,
					Kind:      "CustomRule",
					Rationale: "Ensure containers are not privileged",
				},
			},
		},
	}

	err = f.Client.Create(context.TODO(), tpValid, nil)
	if err != nil {
		t.Fatalf("Failed to create valid TailoredProfile: %v", err)
	}
	defer f.Client.Delete(context.TODO(), tpValid)

	// Should be ready since it only has CustomRules
	err = f.WaitForTailoredProfileStatus(testNamespace, tpValidName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatalf("Valid TailoredProfile did not become ready: %v", err)
	}
	t.Logf("TailoredProfile %s with only CustomRules is ready as expected", tpValidName)

	// Step 6: Create a TailoredProfile with only regular Rules (should work)
	tpRegularName := fmt.Sprintf("%s-tp-regular", testName)
	tpRegular := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpRegularName,
			Namespace: testNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "Regular Rules Only Test",
			Description: "This profile correctly uses only regular Rules",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "ocp4-cluster-version-operator-exists",
					Rationale: "Make sure cluster version operator exists",
				},
				{
					Name:      "ocp4-kubeadmin-removed",
					Kind:      "Rule", // Explicitly set Kind to Rule
					Rationale: "Ensure kubeadmin user has been removed",
				},
			},
		},
	}

	err = f.Client.Create(context.TODO(), tpRegular, nil)
	if err != nil {
		t.Fatalf("Failed to create regular TailoredProfile: %v", err)
	}
	defer f.Client.Delete(context.TODO(), tpRegular)

	// Should be ready since it only has regular Rules
	err = f.WaitForTailoredProfileStatus(testNamespace, tpRegularName, compv1alpha1.TailoredProfileStateReady)
	if err != nil {
		t.Fatalf("Regular TailoredProfile did not become ready: %v", err)
	}
	t.Logf("TailoredProfile %s with only regular Rules is ready as expected", tpRegularName)

	// Step 7: Test updating from valid to invalid (adding a different rule type)
	// Get the valid CustomRule-only profile
	tpToUpdate := &compv1alpha1.TailoredProfile{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: tpValidName, Namespace: testNamespace}, tpToUpdate)
	if err != nil {
		t.Fatalf("Failed to get TailoredProfile for update: %v", err)
	}

	// Update to add a regular Rule, making it invalid
	tpToUpdateCopy := tpToUpdate.DeepCopy()
	tpToUpdateCopy.Spec.EnableRules = append(tpToUpdateCopy.Spec.EnableRules, compv1alpha1.RuleReferenceSpec{
		Name:      "ocp4-cluster-version-operator-exists",
		Kind:      "Rule",
		Rationale: "Adding regular rule to make it invalid",
	})

	err = f.Client.Update(context.TODO(), tpToUpdateCopy)
	if err != nil {
		t.Fatalf("Failed to update TailoredProfile: %v", err)
	}

	// Should go to Error state
	err = f.WaitForTailoredProfileStatus(testNamespace, tpValidName, compv1alpha1.TailoredProfileStateError)
	if err != nil {
		t.Fatalf("Updated TailoredProfile did not enter Error state: %v", err)
	}
	t.Logf("TailoredProfile %s correctly went to Error state after adding mixed rule types", tpValidName)

	t.Log("TestTailoredProfileRejectsMixedRuleTypes completed successfully")
}

func TestSuiteWithContentThatDoesNotMatch(t *testing.T) {
	t.Parallel()
	f := framework.Global

	pbName := framework.GetObjNameFromTest(t)
	baselineImage := fmt.Sprintf("%s:%s", brokenContentImagePath, "broken_os_detection")
	origPb, err := f.CreateProfileBundle(pbName, baselineImage, framework.RhcosContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle: %s", err)
	}
	// This should get cleaned up at the end of the test
	defer f.Client.Delete(context.TODO(), origPb)
	if err = f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("failed waiting for the ProfileBundle to become available: %s", err)
	}

	suiteName := "test-suite-with-non-matching-content"
	testSuite := &compv1alpha1.ComplianceSuite{
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
					Name: fmt.Sprintf("%s-workers-scan", suiteName),
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: baselineImage,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      "ssg-rhcos4-ds.xml",
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug:             true,
							ShowNotApplicable: true,
						},
						NodeSelector: map[string]string{
							"node-role.kubernetes.io/worker": "",
						},
					},
				},
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err = f.Client.Create(context.TODO(), testSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), testSuite)

	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNotApplicable)
	if err != nil {
		t.Fatal(err)
	}
	err = f.SuiteErrorMessageMatchesRegex(f.OperatorNamespace, suiteName, "The suite result is not applicable.*")
	if err != nil {
		t.Fatal(err)
	}
}

func TestScanSettingBinding(t *testing.T) {
	t.Parallel()
	f := framework.Global
	objName := framework.GetObjNameFromTest(t)
	const defaultCpuLimit = "100m"
	const testMemoryLimit = "432Mi"

	rhcosPb := &compv1alpha1.ProfileBundle{}
	err := f.Client.Get(context.TODO(), types.NamespacedName{Name: "rhcos4", Namespace: f.OperatorNamespace}, rhcosPb)
	if err != nil {
		t.Fatalf("unable to get rhcos4 profile bundle required for test: %s", err)
	}

	rhcos4e8profile := &compv1alpha1.Profile{}
	key := types.NamespacedName{Namespace: f.OperatorNamespace, Name: rhcosPb.Name + "-e8"}
	if err := f.Client.Get(context.TODO(), key, rhcos4e8profile); err != nil {
		t.Fatal(err)
	}

	rhcos4moderateprofile := &compv1alpha1.Profile{}
	moderateKey := types.NamespacedName{Namespace: f.OperatorNamespace, Name: rhcosPb.Name + "-moderate"}
	if err := f.Client.Get(context.TODO(), moderateKey, rhcos4moderateprofile); err != nil {
		t.Fatal(err)
	}

	scanSettingName := objName + "-setting"
	scanSetting := compv1alpha1.ScanSetting{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingName,
			Namespace: f.OperatorNamespace,
		},
		ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
			AutoApplyRemediations: false,
		},
		ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
			Debug: true,
			ScanLimits: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceMemory: resource.MustParse(testMemoryLimit),
			},
		},
		Roles: []string{"master", "worker"},
	}

	if err := f.Client.Create(context.TODO(), &scanSetting, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSetting)

	scanSettingBindingName := "generated-suite"
	scanSettingBinding := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingBindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			// TODO: test also OCP profile when it works completely
			{
				Name:     rhcos4e8profile.Name,
				Kind:     "Profile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
			{
				Name:     rhcos4moderateprofile.Name,
				Kind:     "Profile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			Name:     scanSetting.Name,
			Kind:     "ScanSetting",
			APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}

	if err := f.Client.Create(context.TODO(), &scanSettingBinding, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSettingBinding)

	// Wait until the suite finishes, thus verifying the suite exists
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, scanSettingBindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	masterScanKey := types.NamespacedName{Namespace: f.OperatorNamespace, Name: rhcos4e8profile.Name + "-master"}
	masterScan := &compv1alpha1.ComplianceScan{}
	if err := f.Client.Get(context.TODO(), masterScanKey, masterScan); err != nil {
		t.Fatal(err)
	}

	if masterScan.Spec.Debug != true {
		t.Fatal("Expected that the settings set debug to true in master scan")
	}

	workerScanKey := types.NamespacedName{Namespace: f.OperatorNamespace, Name: rhcos4e8profile.Name + "-worker"}
	workerScan := &compv1alpha1.ComplianceScan{}
	if err := f.Client.Get(context.TODO(), workerScanKey, workerScan); err != nil {
		t.Fatal(err)
	}

	if workerScan.Spec.Debug != true {
		t.Fatal("Expected that the settings set debug to true in workers scan")
	}

	moderateMasterScanKey := types.NamespacedName{Namespace: f.OperatorNamespace, Name: rhcos4moderateprofile.Name + "-master"}
	moderateMasterScan := &compv1alpha1.ComplianceScan{}
	if err := f.Client.Get(context.TODO(), moderateMasterScanKey, moderateMasterScan); err != nil {
		t.Fatal(err)
	}

	if moderateMasterScan.Spec.Debug != true {
		t.Fatal("Expected that the settings set debug to true in moderate master scan")
	}

	moderateWorkerScanKey := types.NamespacedName{Namespace: f.OperatorNamespace, Name: rhcos4moderateprofile.Name + "-worker"}
	moderateWorkerScan := &compv1alpha1.ComplianceScan{}
	if err := f.Client.Get(context.TODO(), moderateWorkerScanKey, moderateWorkerScan); err != nil {
		t.Fatal(err)
	}

	if moderateWorkerScan.Spec.Debug != true {
		t.Fatal("Expected that the settings set debug to true in moderate worker scan")
	}

	podList := &corev1.PodList{}
	if err := f.Client.List(context.TODO(), podList, client.InNamespace(f.OperatorNamespace), client.MatchingLabels(map[string]string{
		"workload": "scanner",
	})); err != nil {
		t.Fatal(err)
	}
	// check if the scanning pod has properly been created and has limits set
	for _, pod := range podList.Items {
		if strings.Contains(pod.Name, masterScan.Name) || strings.Contains(pod.Name, workerScan.Name) ||
			strings.Contains(pod.Name, moderateMasterScan.Name) || strings.Contains(pod.Name, moderateWorkerScan.Name) {
			if err := framework.WaitForPod(framework.CheckPodLimit(f.KubeClient, pod.Name, f.OperatorNamespace, defaultCpuLimit, testMemoryLimit)); err != nil {
				t.Fatal(err)
			}
		}
	}

}
func TestScanSettingBindingUsesDefaultScanSetting(t *testing.T) {
	t.Parallel()
	f := framework.Global
	objName := framework.GetObjNameFromTest(t)
	scanSettingBindingName := objName + "-binding"
	scanSettingBinding := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingBindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     "ocp4-cis",
				Kind:     "Profile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
		},
	}
	if err := f.Client.Create(context.TODO(), &scanSettingBinding, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSettingBinding)

	// Wait until the suite finishes
	err := f.WaitForSuiteScansStatus(f.OperatorNamespace, scanSettingBindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	bindingKey := types.NamespacedName{Namespace: f.OperatorNamespace, Name: scanSettingBindingName}
	binding := &compv1alpha1.ScanSettingBinding{}
	if err := f.Client.Get(context.TODO(), bindingKey, binding); err != nil {
		t.Fatal(err)
	}

	// Make sure the binding used the `default` ScanSetting.
	if binding.SettingsRef.Name != "default" {
		t.Fatal("Expected the settings reference to use the default ScanSetting")
	}
}

// TestTailoringEnabledRulesGenerateRemediations verifies that when a rule is added via EnableRules,
// it behaves as a normal rule (not manual), reports PASS/FAIL status, and generates remediations when it fails.
// This complements TestTailoringManualRulesDoesNotGenerateRemediations which verifies the opposite behavior.
func TestTailoringEnabledRulesGenerateRemediations(t *testing.T) {
	t.Parallel()
	f := framework.Global
	var baselineImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "kubeletconfig")
	// This rule is expected to fail in the test environment, allowing us to verify remediation generation
	const requiredRule = "oauth-or-oauthclient-token-maxage"
	// Use short but meaningful names to fit within Kubernetes 63-char DNS name limit
	pbName := "enabled-rules-rem"
	enabledTPName := "enabled-rules-rem"
	prefixName := func(profName, ruleBaseName string) string { return profName + "-" + ruleBaseName }

	ocpPb, err := f.CreateProfileBundle(pbName, baselineImage, framework.OcpContentFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ocpPb)
	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}

	// Check that the rule we are going to test exists
	requiredRuleName := prefixName(pbName, requiredRule)
	err, found := framework.Global.DoesRuleExist(f.OperatorNamespace, requiredRuleName)
	if err != nil {
		t.Fatal(err)
	} else if !found {
		t.Fatalf("Expected rule %s not found", requiredRuleName)
	}

	// Create a TailoredProfile with the rule as an enabled rule
	enabledScanName := fmt.Sprintf("%s", enabledTPName)

	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      enabledTPName,
			Namespace: f.OperatorNamespace,
			Annotations: map[string]string{
				compv1alpha1.DisableOutdatedReferenceValidation: "true",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "enabled-rules-test",
			Description: "A test tailored profile to verify enabled rules generate remediations",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      prefixName(pbName, requiredRule),
					Rationale: "To verify enabled rule behavior",
				},
			},
		},
	}

	err = f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      enabledTPName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     enabledTPName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}

	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// Wait for the scan to complete
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, enabledTPName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	// Verify that the rule shows FAIL (not MANUAL) status
	enabledCheckName := fmt.Sprintf("%s-%s", enabledScanName, requiredRule)
	actualCheck := &compv1alpha1.ComplianceCheckResult{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{
		Name:      enabledCheckName,
		Namespace: f.OperatorNamespace,
	}, actualCheck)
	if err != nil {
		t.Fatalf("Failed to get check result: %v", err)
	}

	// Verify the status is FAIL (this rule is expected to fail in the test environment)
	if actualCheck.Status != compv1alpha1.CheckResultFail {
		t.Fatalf("Expected check result status to be FAIL, but got %s", actualCheck.Status)
	}

	// Verify that a remediation is created for the failed enabled rule
	// This is the key difference from manual rules which never create remediations
	inNs := client.InNamespace(f.OperatorNamespace)
	enabledRemList := &compv1alpha1.ComplianceRemediationList{}
	enabledWithLabel := client.MatchingLabels{
		compv1alpha1.ComplianceScanLabel: enabledScanName,
	}
	err = f.Client.List(context.TODO(), enabledRemList, inNs, enabledWithLabel)
	if err != nil {
		t.Fatal(err)
	}

	// For enabled rules that fail, remediations should be created
	expectedRemediationName := fmt.Sprintf("%s-%s", enabledScanName, requiredRule)
	foundRemediation := false
	for _, rem := range enabledRemList.Items {
		if rem.Name == expectedRemediationName {
			foundRemediation = true
			t.Logf("Successfully verified remediation %s was created for failed enabled rule", expectedRemediationName)
			break
		}
	}
	if !foundRemediation {
		t.Fatalf("Expected remediation %s for failed enabled rule, but none found", expectedRemediationName)
	}
}

func TestResultServerHTTPVersion(t *testing.T) {
	t.Parallel()
	f := framework.Global
	endpoints := []string{
		fmt.Sprintf("https://metrics.%s.svc:8585/metrics-co", f.OperatorNamespace),
		fmt.Sprintf("http://metrics.%s.svc:8383/metrics", f.OperatorNamespace),
	}

	expectedHTTPVersion := "HTTP/1.1"
	for _, endpoint := range endpoints {
		err := f.AssertMetricsEndpointUsesHTTPVersion(endpoint, expectedHTTPVersion)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestRuleHasProfileAnnotation(t *testing.T) {
	t.Parallel()
	f := framework.Global
	const requiredRule = "ocp4-file-groupowner-worker-kubeconfig"
	const expectedRuleProfileAnnotation = "ocp4-pci-dss-node,ocp4-moderate-node,ocp4-nerc-cip-node,ocp4-cis-node,ocp4-high-node"
	err, found := f.DoesRuleExist(f.OperatorNamespace, requiredRule)
	if err != nil {
		t.Fatal(err)
	} else if !found {
		t.Fatalf("Expected rule %s not found", requiredRule)
	}

	// Check if requiredRule has the correct profile annotation
	rule := &compv1alpha1.Rule{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{
		Name:      requiredRule,
		Namespace: f.OperatorNamespace,
	}, rule)
	if err != nil {
		t.Fatal(err)
	}
	expectedProfiles := strings.Split(expectedRuleProfileAnnotation, ",")
	for _, profileName := range expectedProfiles {
		if !f.AssertProfileInRuleAnnotation(rule, profileName) {
			t.Fatalf("expected to find profile %s in rule %s", profileName, rule.Name)
		}
	}
}

func TestScanCleansUpComplianceCheckResults(t *testing.T) {
	f := framework.Global
	t.Parallel()

	tpName := framework.GetObjNameFromTest(t)
	bindingName := tpName + "-binding"

	// create a tailored profile
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tpName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       tpName,
			Description: tpName,
			Extends:     "ocp4-cis",
		},
	}

	err := f.Client.Create(context.TODO(), tp, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tp)

	// run a scan
	ssb := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     tpName,
				Kind:     "TailoredProfile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			Name:     "default",
			Kind:     "ScanSetting",
			APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}
	err = f.Client.Create(context.TODO(), &ssb, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &ssb)

	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	// verify a compliance check result exists
	checkName := tpName + "-audit-profile-set"
	checkResult := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      checkName,
			Namespace: f.OperatorNamespace,
		},
		ID:       "xccdf_org.ssgproject.content_rule_audit_profile_set",
		Status:   compv1alpha1.CheckResultFail,
		Severity: compv1alpha1.CheckResultSeverityMedium,
	}
	err = f.AssertHasCheck(bindingName, tpName, checkResult)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AssertRemediationExists(checkName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}

	// update tailored profile to exclude the rule before we kick off another run
	tpGet := &compv1alpha1.TailoredProfile{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: tpName, Namespace: f.OperatorNamespace}, tpGet)
	if err != nil {
		t.Fatal(err)
	}

	tpUpdate := tpGet.DeepCopy()
	ruleName := "ocp4-audit-profile-set"
	tpUpdate.Spec.DisableRules = []compv1alpha1.RuleReferenceSpec{
		{
			Name:      ruleName,
			Rationale: "testing to ensure scan results are cleaned up",
		},
	}

	err = f.Client.Update(context.TODO(), tpUpdate)
	if err != nil {
		t.Fatal(err)
	}

	// rerun the scan
	err = f.ReRunScan(tpName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	// verify the compliance check result doesn't exist, which will also
	// mean the compliance remediation should also be gone
	if err = f.AssertScanDoesNotContainCheck(tpName, checkName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}
	if err = f.AssertRemediationDoesNotExists(checkName, f.OperatorNamespace); err != nil {
		t.Fatal(err)
	}
}

func TestScanWithoutBundlePassesDeprecationCheck(t *testing.T) {
	t.Parallel()
	f := framework.Global

	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile: "xccdf_org.ssgproject.content_profile_moderate",
			// Make the ProfileBundle lookup fail because the
			// Content and ContentImage mismatch. This means the
			// operator can't check if the profile is deprecated
			// because it can't reliably know which bundle it came
			// from and hasn't parsed that specific datastream. In
			// cases like this, the profile deprecation logic
			// shouldn't prevent the scan. Advanced users might use
			// this technique to point to their own custom content,
			// which is rare but possible.
			Content:      framework.OcpContentFile,
			ContentImage: contentImagePath,
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}

	// Create the scan directly since we want to set these attributes
	// directly, and not assume the existing ProfileBundles.
	err := f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatalf("failed to create scan %s: %s", scanName, err)
	}
	defer f.Client.Delete(context.TODO(), testScan)

	// Wait for the scan to reach Done phase
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	// Get the final scan state
	if err = f.Client.Get(context.TODO(), types.NamespacedName{Name: scanName, Namespace: f.OperatorNamespace}, testScan); err != nil {
		t.Fatal(err)
	}

	// The scan should NOT fail on profile deprecation check when ProfileBundle matching fails
	if testScan.Status.ErrorMessage == "Could not check whether the Profile used by ComplianceScan is deprecated" {
		t.Fatal(errors.New("scan should not fail on profile deprecation check when ProfileBundle matching fails"))
	}

	t.Logf("Scan completed with result: %s", testScan.Status.Result)
}

// TestRuleVariableAnnotation tests that rules with variables have the correct annotation
func TestRuleVariableAnnotation(t *testing.T) {
	t.Parallel()
	f := framework.Global

	// Test cases for rules that should have variable annotations
	testCases := []struct {
		ruleName         string
		expectedVariable string
		description      string
	}{
		{
			ruleName:         "ocp4-configure-network-policies-namespaces",
			expectedVariable: "var-network-policies-namespaces-exempt-regex",
			description:      "Network policies namespace exemption variable",
		},
		{
			ruleName:         "ocp4-resource-requests-limits-in-statefulset",
			expectedVariable: "var-statefulset-limit-namespaces-exempt-regex",
			description:      "StatefulSet resource limit namespace exemption variable",
		},
		{
			ruleName:         "ocp4-api-server-request-timeout",
			expectedVariable: "var-api-min-request-timeout",
			description:      "API server request timeout variable",
		},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.ruleName, func(t *testing.T) {
			// Get the rule
			rule := &compv1alpha1.Rule{}
			err := f.Client.Get(context.TODO(), types.NamespacedName{
				Name:      tc.ruleName,
				Namespace: f.OperatorNamespace,
			}, rule)
			if err != nil {
				t.Fatalf("Failed to get rule %s: %v", tc.ruleName, err)
			}

			// Check that the rule has the variable annotation
			variableAnnotation, exists := rule.Annotations[compv1alpha1.RuleVariableAnnotationKey]
			if !exists {
				t.Fatalf("Rule %s is missing the %s annotation. This is a regression of CMP-3582",
					tc.ruleName, compv1alpha1.RuleVariableAnnotationKey)
			}

			// Verify the annotation contains the expected variable
			if variableAnnotation != tc.expectedVariable {
				t.Fatalf("Rule %s has incorrect variable annotation.\nExpected: %s\nGot: %s\nDescription: %s",
					tc.ruleName, tc.expectedVariable, variableAnnotation, tc.description)
			}

			if tc.expectedVariable == "var-api-min-request-timeout" {
				prefix, _, ok := strings.Cut(tc.ruleName, "-")
				if !ok {
					t.Fatalf("rule name %q has no product prefix", tc.ruleName)
				}
				variableCRName := prefix + "-" + tc.expectedVariable
				v := &compv1alpha1.Variable{}
				err = f.Client.Get(context.TODO(), types.NamespacedName{
					Name:      variableCRName,
					Namespace: f.OperatorNamespace,
				}, v)
				if err != nil {
					t.Fatalf("Failed to get Variable %s: %v", variableCRName, err)
				}
				const wantDefault = "3600"
				if v.Value != wantDefault {
					t.Fatalf("Variable %s default Value: want %q, got %q", variableCRName, wantDefault, v.Value)
				}
				t.Logf("Variable %s has expected default value %s", variableCRName, wantDefault)
			}

			t.Logf("Rule %s correctly has variable annotation: %s", tc.ruleName, tc.expectedVariable)
		})
	}
}

// Verifies that setting timeout to "0s" disables the timeout functionality
func TestTimeoutDisabledWithZeroValue(t *testing.T) {
	t.Parallel()
	f := framework.Global

	// Create a new ScanSetting with timeout set to 0s (disabled)
	scanSettingName := framework.GetObjNameFromTest(t) + "-scansetting"
	scanSetting := compv1alpha1.ScanSetting{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanSettingName,
			Namespace: f.OperatorNamespace,
		},
		ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
			AutoApplyRemediations: false,
		},
		ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
			Timeout: "0s",
		},
		Roles: []string{"master", "worker"},
	}
	if err := f.Client.Create(context.TODO(), &scanSetting, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSetting)

	// Bind the ScanSetting to a Profile
	bindingName := framework.GetObjNameFromTest(t) + "-binding"
	scanSettingBinding := compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				Name:     "ocp4-moderate",
				Kind:     "Profile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			Name:     scanSetting.Name,
			Kind:     "ScanSetting",
			APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}
	if err := f.Client.Create(context.TODO(), &scanSettingBinding, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), &scanSettingBinding)

	// Wait for the scan to complete successfully
	// With timeout set to 0s, the scan should not timeout and complete normally
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, bindingName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatal(err)
	}

	// Verify that scans do not have the timeout annotation
	suite := &compv1alpha1.ComplianceSuite{}
	key := types.NamespacedName{Name: bindingName, Namespace: f.OperatorNamespace}
	if err := f.Client.Get(context.TODO(), key, suite); err != nil {
		t.Fatal(err)
	}

	for _, scanStatus := range suite.Status.ScanStatuses {
		// Verify the scan does not have the timeout annotation
		scan := &compv1alpha1.ComplianceScan{}
		scanKey := types.NamespacedName{Name: scanStatus.Name, Namespace: f.OperatorNamespace}
		if err := f.Client.Get(context.TODO(), scanKey, scan); err != nil {
			t.Fatalf("failed to get scan %s: %s", scanStatus.Name, err)
		}
		if _, hasTimeout := scan.Annotations[compv1alpha1.ComplianceScanTimeoutAnnotation]; hasTimeout {
			t.Fatalf("scan %s should not have timeout annotation when timeout is disabled (0s), but it does", scanStatus.Name)
		}
	}
}

// Verifies that access modes and Storage class are configurable through ComplianceSuite and ComplianceScan
// TestResultServerSAAndSecurityContext tests that resultserver uses a separate service account
// with correct security context settings
func TestResultServerSAAndSecurityContext(t *testing.T) {
	t.Parallel()
	f := framework.Global

	suiteName := framework.GetObjNameFromTest(t)
	scanName := fmt.Sprintf("%s-scan", suiteName)

	// Get the compliance-operator pod to extract expected security context values
	pods, err := f.KubeClient.CoreV1().Pods(f.OperatorNamespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: "name=compliance-operator",
	})
	if err != nil {
		t.Fatalf("failed to list compliance-operator pods: %s", err)
	}
	if len(pods.Items) == 0 {
		t.Fatal("no compliance-operator pods found")
	}

	operatorSC := pods.Items[0].Spec.SecurityContext
	if operatorSC == nil {
		t.Fatal("compliance-operator pod has no security context")
	}
	if operatorSC.FSGroup == nil {
		t.Fatal("compliance-operator pod has no fsGroup")
	}
	if operatorSC.SELinuxOptions == nil {
		t.Fatal("compliance-operator pod has no seLinuxOptions")
	}

	expectedFSGroup := *operatorSC.FSGroup
	expectedSELinuxLevel := operatorSC.SELinuxOptions.Level

	suite := &compv1alpha1.ComplianceSuite{
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
						NodeSelector: map[string]string{
							"node-role.kubernetes.io/master": "",
						},
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
		t.Fatalf("failed to create suite: %s", err)
	}
	defer f.Client.Delete(context.TODO(), suite)
	if err := f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseRunning); err != nil {
		t.Fatalf("failed waiting for scan to reach RUNNING phase: %s", err)
	}

	// Wait for the resultserver pod to appear (with retry)
	var rsPod corev1.Pod
	err = wait.Poll(framework.RetryInterval, framework.Timeout, func() (bool, error) {
		rsPods, listErr := f.KubeClient.CoreV1().Pods(f.OperatorNamespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: fmt.Sprintf("compliance.openshift.io/scan-name=%s,workload=resultserver", scanName),
		})
		if listErr != nil {
			return false, listErr
		}
		if len(rsPods.Items) == 0 {
			// Pod not found yet, retry
			return false, nil
		}
		rsPod = rsPods.Items[0]
		return true, nil
	})
	if err != nil {
		t.Fatalf("failed to find resultserver pod: %s", err)
	}

	// Verify the resultserver pod uses the correct service account
	expectedServiceAccount := "resultserver"
	if rsPod.Spec.ServiceAccountName != expectedServiceAccount {
		t.Fatalf("service account mismatch: expected %s, got %s", expectedServiceAccount, rsPod.Spec.ServiceAccountName)
	}

	// Verify all security context fields match expected values
	rsSC := rsPod.Spec.SecurityContext
	if rsSC == nil {
		t.Fatal("resultserver pod has no security context")
	}
	if rsSC.FSGroup == nil || *rsSC.FSGroup != expectedFSGroup {
		t.Fatalf("fsGroup mismatch: expected %d, got %v", expectedFSGroup, rsSC.FSGroup)
	}
	if rsSC.RunAsNonRoot == nil || !*rsSC.RunAsNonRoot {
		t.Fatal("runAsNonRoot must be true")
	}
	if rsSC.RunAsUser == nil || *rsSC.RunAsUser != int64(expectedFSGroup) {
		t.Fatalf("runAsUser mismatch: expected %d, got %v", expectedFSGroup, rsSC.RunAsUser)
	}
	if rsSC.SELinuxOptions == nil || rsSC.SELinuxOptions.Level != expectedSELinuxLevel {
		t.Fatalf("seLinuxOptions.Level mismatch: expected %s, got %v", expectedSELinuxLevel, rsSC.SELinuxOptions)
	}
	if rsSC.SeccompProfile == nil || rsSC.SeccompProfile.Type != "RuntimeDefault" {
		t.Fatalf("seccompProfile.Type mismatch: expected RuntimeDefault, got %v", rsSC.SeccompProfile)
	}

	// Wait for the scan to complete
	if err := f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant); err != nil {
		t.Fatalf("failed waiting for scan to complete: %s", err)
	}
}

func TestCELProfileBundle(t *testing.T) {
	t.Parallel()
	f := framework.Global

	pbName := framework.GetObjNameFromTest(t)
	celContentImage := brokenContentImagePath + ":cel_content"

	pb, err := f.CreateProfileBundleWithCEL(pbName, celContentImage, framework.RhcosContentFile, framework.CelContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle with CEL content: %s", err)
	}
	defer f.Client.Delete(context.TODO(), pb)

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("ProfileBundle did not reach VALID state: %s", err)
	}
	t.Log("ProfileBundle is VALID")

	// Verify that XCCDF profiles were also parsed (the content image has ssg-rhcos4-ds.xml)
	if err := f.AssertProfileBundleMustHaveParsedRules(pbName); err != nil {
		t.Fatalf("ProfileBundle should have parsed XCCDF rules: %s", err)
	}

	// Verify CEL profile was created
	celProfileName := pbName + "-cel-e2e-test-profile"
	celProfile := &compv1alpha1.Profile{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{
		Name: celProfileName, Namespace: f.OperatorNamespace,
	}, celProfile)
	if err != nil {
		t.Fatalf("CEL profile not found: %s", err)
	}
	t.Logf("CEL profile %s exists", celProfileName)

	// Verify CEL profile annotations
	if celProfile.Annotations[compv1alpha1.ScannerTypeAnnotation] != string(compv1alpha1.ScannerTypeCEL) {
		t.Fatalf("expected scanner-type annotation CEL, got %s", celProfile.Annotations[compv1alpha1.ScannerTypeAnnotation])
	}
	if celProfile.Annotations[compv1alpha1.ProductTypeAnnotation] != string(compv1alpha1.ScanTypePlatform) {
		t.Fatalf("expected product-type annotation Platform, got %s", celProfile.Annotations[compv1alpha1.ProductTypeAnnotation])
	}
	if celProfile.Labels[compv1alpha1.ProfileBundleOwnerLabel] != pbName {
		t.Fatalf("expected ProfileBundleOwnerLabel %s, got %s", pbName, celProfile.Labels[compv1alpha1.ProfileBundleOwnerLabel])
	}

	// Verify CEL profile has correct rules
	expectedRules := []string{
		pbName + "-check-default-namespace-has-no-pods",
		pbName + "-check-default-sa-exists-in-kube-system",
		pbName + "-check-namespaces-have-network-policies",
		pbName + "-check-no-privileged-containers",
	}
	if len(celProfile.Rules) != len(expectedRules) {
		t.Fatalf("expected %d rules in CEL profile, got %d", len(expectedRules), len(celProfile.Rules))
	}
	for _, expectedRule := range expectedRules {
		found := false
		for _, rule := range celProfile.Rules {
			if string(rule) == expectedRule {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("rule %s not found in CEL profile", expectedRule)
		}
	}
	t.Logf("CEL profile has all %d expected rules", len(expectedRules))

	// Verify CEL rules exist and have correct attributes
	celRuleNames := []string{
		"check-default-namespace-has-no-pods",
		"check-default-sa-exists-in-kube-system",
		"check-namespaces-have-network-policies",
		"check-no-privileged-containers",
	}
	for _, ruleName := range celRuleNames {
		fullRuleName := pbName + "-" + ruleName
		rule := &compv1alpha1.Rule{}
		err = f.Client.Get(context.TODO(), types.NamespacedName{
			Name: fullRuleName, Namespace: f.OperatorNamespace,
		}, rule)
		if err != nil {
			t.Fatalf("CEL rule %s not found: %s", fullRuleName, err)
		}

		if rule.ScannerType != compv1alpha1.ScannerTypeCEL {
			t.Fatalf("rule %s: expected ScannerType CEL, got %s", fullRuleName, rule.ScannerType)
		}
		if rule.RulePayload.Expression == "" {
			t.Fatalf("rule %s: expression should not be empty", fullRuleName)
		}
		if len(rule.RulePayload.Inputs) == 0 {
			t.Fatalf("rule %s: should have at least one input", fullRuleName)
		}
		if rule.Labels[compv1alpha1.ProfileBundleOwnerLabel] != pbName {
			t.Fatalf("rule %s: expected ProfileBundleOwnerLabel %s, got %s", fullRuleName, pbName, rule.Labels[compv1alpha1.ProfileBundleOwnerLabel])
		}
		if rule.Annotations[compv1alpha1.RuleIDAnnotationKey] == "" {
			t.Fatalf("rule %s: missing RuleIDAnnotationKey", fullRuleName)
		}
		if rule.Annotations[compv1alpha1.RuleProfileAnnotationKey] == "" {
			t.Fatalf("rule %s: missing RuleProfileAnnotationKey", fullRuleName)
		}
		t.Logf("CEL rule %s verified: ScannerType=CEL, Expression present, %d inputs", fullRuleName, len(rule.RulePayload.Inputs))
	}

	// Verify the privileged-containers rule has high severity
	privRule := &compv1alpha1.Rule{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{
		Name: pbName + "-check-no-privileged-containers", Namespace: f.OperatorNamespace,
	}, privRule)
	if err != nil {
		t.Fatalf("failed to get privileged containers rule: %s", err)
	}
	if privRule.Severity != "high" {
		t.Fatalf("expected severity high for privileged containers rule, got %s", privRule.Severity)
	}
	t.Log("CEL ProfileBundle parsing test completed successfully")
}

func TestCELProfileScan(t *testing.T) {
	t.Parallel()
	f := framework.Global

	testName := framework.GetObjNameFromTest(t)
	pbName := testName + "-pb"
	ssbName := testName + "-ssb"
	testNamespace := f.OperatorNamespace
	celContentImage := brokenContentImagePath + ":cel_content"

	// Create ProfileBundle with CEL content
	pb, err := f.CreateProfileBundleWithCEL(pbName, celContentImage, framework.RhcosContentFile, framework.CelContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle: %s", err)
	}
	defer f.Client.Delete(context.TODO(), pb)

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("ProfileBundle did not reach VALID state: %s", err)
	}

	// Bind the CEL profile to a ScanSetting via ScanSettingBinding
	celProfileName := pbName + "-cel-e2e-test-profile"
	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ssbName,
			Namespace: testNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "Profile",
				Name:     celProfileName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}
	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatalf("Failed to create ScanSettingBinding: %v", err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	err = f.WaitForScanSettingBindingStatus(testNamespace, ssbName, compv1alpha1.ScanSettingBindingPhaseReady)
	if err != nil {
		t.Fatalf("ScanSettingBinding did not become ready: %v", err)
	}
	t.Log("ScanSettingBinding is ready")

	// The suite name matches the SSB name
	suiteName := ssbName

	// The CEL rules check for pods in default namespace, network policies, and privileged containers.
	// In most clusters this will be non-compliant. Accept either result - we just need the scan to complete.
	err = f.WaitForSuiteScansStatus(testNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		err = f.WaitForSuiteScansStatus(testNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
		if err != nil {
			t.Fatalf("CEL scan did not complete: %v", err)
		}
		t.Log("CEL scan completed as COMPLIANT")
	} else {
		t.Log("CEL scan completed as NON-COMPLIANT")
	}

	// Verify ComplianceCheckResults were created for the CEL rules
	scanName := celProfileName
	celRuleNames := []string{
		"check-default-namespace-has-no-pods",
		"check-default-sa-exists-in-kube-system",
		"check-namespaces-have-network-policies",
		"check-no-privileged-containers",
	}
	for _, ruleName := range celRuleNames {
		checkName := fmt.Sprintf("%s-%s", scanName, ruleName)
		check := &compv1alpha1.ComplianceCheckResult{}
		err = f.Client.Get(context.TODO(), types.NamespacedName{
			Name: checkName, Namespace: testNamespace,
		}, check)
		if err != nil {
			t.Fatalf("ComplianceCheckResult %s not found: %v", checkName, err)
		}

		if check.Status != compv1alpha1.CheckResultPass && check.Status != compv1alpha1.CheckResultFail {
			t.Fatalf("check %s has unexpected status: %s", checkName, check.Status)
		}
		t.Logf("ComplianceCheckResult %s: status=%s, severity=%s", checkName, check.Status, check.Severity)
	}

	t.Log("CEL Profile scan test completed successfully - all 4 CEL rules produced check results")
}

func TestCELWithXCCDFProfileScan(t *testing.T) {
	t.Parallel()
	f := framework.Global

	testName := framework.GetObjNameFromTest(t)
	pbName := testName + "-pb"
	ssbName := testName + "-ssb"
	testNamespace := f.OperatorNamespace
	celContentImage := brokenContentImagePath + ":cel_content"

	pb, err := f.CreateProfileBundleWithCEL(pbName, celContentImage, framework.OcpContentFile, framework.CelContentFile)
	if err != nil {
		t.Fatalf("failed to create ProfileBundle: %s", err)
	}
	defer f.Client.Delete(context.TODO(), pb)

	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("ProfileBundle did not reach VALID state: %s", err)
	}

	celProfileName := pbName + "-cel-e2e-test-profile"
	xccdfProfileName := pbName + "-cis"

	// Bind both a CEL profile and an XCCDF profile from the same bundle in one SSB
	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ssbName,
			Namespace: testNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "Profile",
				Name:     celProfileName,
			},
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "Profile",
				Name:     xccdfProfileName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}
	err = f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatalf("Failed to create ScanSettingBinding: %v", err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	err = f.WaitForScanSettingBindingStatus(testNamespace, ssbName, compv1alpha1.ScanSettingBindingPhaseReady)
	if err != nil {
		t.Fatalf("ScanSettingBinding did not become ready: %v", err)
	}
	t.Log("ScanSettingBinding is ready with CEL + XCCDF profiles")

	suiteName := ssbName

	err = f.WaitForSuiteScansStatus(testNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		err = f.WaitForSuiteScansStatus(testNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
		if err != nil {
			t.Fatalf("Suite did not complete: %v", err)
		}
	}
	t.Log("Suite completed")

	// Verify CEL scan produced check results
	celRuleNames := []string{
		"check-default-namespace-has-no-pods",
		"check-default-sa-exists-in-kube-system",
		"check-namespaces-have-network-policies",
		"check-no-privileged-containers",
	}
	for _, ruleName := range celRuleNames {
		checkName := fmt.Sprintf("%s-%s", celProfileName, ruleName)
		check := &compv1alpha1.ComplianceCheckResult{}
		err = f.Client.Get(context.TODO(), types.NamespacedName{
			Name: checkName, Namespace: testNamespace,
		}, check)
		if err != nil {
			t.Fatalf("CEL ComplianceCheckResult %s not found: %v", checkName, err)
		}
		if check.Status != compv1alpha1.CheckResultPass && check.Status != compv1alpha1.CheckResultFail {
			t.Fatalf("CEL check %s has unexpected status: %s", checkName, check.Status)
		}
		t.Logf("CEL check %s: status=%s", checkName, check.Status)
	}

	// Verify XCCDF scan also produced check results
	xccdfChecks := &compv1alpha1.ComplianceCheckResultList{}
	err = f.Client.List(context.TODO(), xccdfChecks, client.MatchingLabels{
		"compliance.openshift.io/scan-name": xccdfProfileName,
	})
	if err != nil {
		t.Fatalf("Failed to list XCCDF check results: %v", err)
	}
	if len(xccdfChecks.Items) == 0 {
		t.Fatalf("No XCCDF ComplianceCheckResults found for scan %s", xccdfProfileName)
	}
	t.Logf("XCCDF scan %s produced %d check results", xccdfProfileName, len(xccdfChecks.Items))

	t.Log("Mixed CEL + XCCDF scan test completed successfully")
}

// TestMultipleProfileBundlesWithTailoredProfiles tests that the profileparser can handle
// multiple ProfileBundles being parsed concurrently without corrupting each other or the
// default bundles, and that scans using TailoredProfiles from each bundle complete successfully.
func TestMultipleProfileBundlesWithTailoredProfiles(t *testing.T) {
	f := framework.Global
	var (
		pb1Image = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_baseline")
		pb2Image = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_mod")
	)

	// Use a short base name so that derived scan/service names stay under the 63-char DNS label limit.
	// The longest name is the result server service: {tpName}-{role}-rs.
	baseName := "multi-pb"

	// Create both ProfileBundles before waiting, so the operator parses them concurrently
	pb1Name := baseName + "-pb1"
	pb1, err := f.CreateProfileBundle(pb1Name, pb1Image, framework.RhcosContentFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), pb1)

	pb2Name := baseName + "-pb2"
	pb2, err := f.CreateProfileBundle(pb2Name, pb2Image, framework.RhcosContentFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), pb2)

	// Wait for both ProfileBundles to become valid
	if err := f.WaitForProfileBundleStatus(pb1Name, compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}
	if err := f.WaitForProfileBundleStatus(pb2Name, compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}

	// Check that default ProfileBundles remain valid after concurrent custom bundle parsing
	if err := f.WaitForProfileBundleStatus("ocp4", compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}
	if err := f.WaitForProfileBundleStatus("rhcos4", compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}

	// Create TailoredProfiles extending from each ProfileBundle using the e8 profile
	tp1Name := baseName + "-tp1"
	tp1 := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tp1Name,
			Namespace: f.OperatorNamespace,
			Annotations: map[string]string{
				compv1alpha1.ProductTypeAnnotation: string(compv1alpha1.ScanTypeNode),
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "Test Multiple ProfileBundles - TP1",
			Description: "TailoredProfile extending from first custom ProfileBundle",
			Extends:     pb1Name + "-e8",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      pb1Name + "-account-disable-post-pw-expiration",
					Rationale: "Test enabling rule from custom ProfileBundle",
				},
			},
			DisableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      pb1Name + "-account-unique-name",
					Rationale: "Test disabling rule from custom ProfileBundle",
				},
			},
		},
	}
	if err := f.Client.Create(context.TODO(), tp1, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tp1)

	tp2Name := baseName + "-tp2"
	tp2 := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tp2Name,
			Namespace: f.OperatorNamespace,
			Annotations: map[string]string{
				compv1alpha1.ProductTypeAnnotation: string(compv1alpha1.ScanTypeNode),
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "Test Multiple ProfileBundles - TP2",
			Description: "TailoredProfile extending from second custom ProfileBundle",
			Extends:     pb2Name + "-e8",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      pb2Name + "-wireless-disable-in-bios",
					Rationale: "Test enabling rule from second custom ProfileBundle",
				},
			},
			DisableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      pb2Name + "-account-unique-name",
					Rationale: "Test disabling rule from second custom ProfileBundle",
				},
			},
		},
	}
	if err := f.Client.Create(context.TODO(), tp2, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), tp2)

	// Wait for both TailoredProfiles to become ready
	if err := f.WaitForTailoredProfileStatus(f.OperatorNamespace, tp1Name, compv1alpha1.TailoredProfileStateReady); err != nil {
		t.Fatal(err)
	}
	if err := f.WaitForTailoredProfileStatus(f.OperatorNamespace, tp2Name, compv1alpha1.TailoredProfileStateReady); err != nil {
		t.Fatal(err)
	}

	// Run scans using both TailoredProfiles to exercise the full workflow
	ssb1Name := baseName + "-ssb1"
	ssb1 := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ssb1Name,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     tp1Name,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}
	if err := f.Client.Create(context.TODO(), ssb1, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ssb1)

	ssb2Name := baseName + "-ssb2"
	ssb2 := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ssb2Name,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     tp2Name,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "default",
		},
	}
	if err := f.Client.Create(context.TODO(), ssb2, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), ssb2)

	// Wait for both suites to complete
	if err := f.WaitForSuiteScansStatusAnyResult(f.OperatorNamespace, ssb1Name, compv1alpha1.PhaseDone,
		compv1alpha1.ResultCompliant, compv1alpha1.ResultNonCompliant, compv1alpha1.ResultNotApplicable); err != nil {
		t.Fatal(err)
	}
	if err := f.WaitForSuiteScansStatusAnyResult(f.OperatorNamespace, ssb2Name, compv1alpha1.PhaseDone,
		compv1alpha1.ResultCompliant, compv1alpha1.ResultNonCompliant, compv1alpha1.ResultNotApplicable); err != nil {
		t.Fatal(err)
	}

	// Verify default ProfileBundles are still valid after concurrent scans
	if err := f.WaitForProfileBundleStatus("ocp4", compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}
	if err := f.WaitForProfileBundleStatus("rhcos4", compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}
}
