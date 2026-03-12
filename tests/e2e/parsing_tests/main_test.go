package parsing_e2e

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var brokenContentImagePath string
var contentImagePath string
var criticalOnly = flag.Bool("critical", false, "run ONLY critical tests")

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

// CRITICAL: Parsed profiles must have version set; required for reporting and content identity.
func TestProfileVersion(t *testing.T) {
	t.Parallel()
	f := framework.Global

	profile := &compv1alpha1.Profile{}
	profileName := "ocp4-cis"
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: f.OperatorNamespace, Name: profileName}, profile); err != nil {
		t.Fatalf("failed to get profile %s: %s", profileName, err)
	}
	if profile.Version == "" {
		t.Fatalf("expected profile %s to have version set", profileName)
	}
}

// CRITICAL: ProfileBundle image updates must refresh Profiles and TailoredProfiles; otherwise scans use stale content.
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

// CRITICAL: ImageStream tag updates must trigger content refresh; primary path for content delivery on OpenShift.
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

	removedRuleName := prefixName(pbName, removedRule)
	err, found := f.DoesRuleExist(pb.Namespace, removedRuleName)
	if err != nil {
		t.Fatal(err)
	} else if !found {
		t.Fatalf("failed to find rule %s in ProfileBundle %s", removedRuleName, pbName)
	}

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

	if err := f.UpdateImageStreamTag(iSName, modifiedImage, f.OperatorNamespace); err != nil {
		t.Fatalf("failed to update image stream %s: %s", iSName, err)
	}
	modifiedImageDigest, err := f.GetImageStreamUpdatedDigest(iSName, f.OperatorNamespace)
	if err != nil {
		t.Fatalf("failed to get digest for image stream %s: %s", iSName, err)
	}
	if err := f.WaitForDeploymentContentUpdate(pbName, modifiedImageDigest); err != nil {
		t.Fatalf("failed waiting for content to update: %s", err)
	}
	if err := f.AssertProfileBundleMustHaveParsedRules(pbName); err != nil {
		t.Fatal(err)
	}

	err, found = f.DoesRuleExist(pb.Namespace, removedRuleName)
	if err != nil {
		t.Fatal(err)
	} else if found {
		t.Fatalf("rule %s unexpectedly found", removedRuleName)
	}

	profilePostUpdate := &compv1alpha1.Profile{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: pb.Namespace, Name: profileName}, profilePostUpdate); err != nil {
		t.Fatalf("failed to get profile %s", profileName)
	}
	found = framework.IsRuleInProfile(unlinkedRuleName, profilePostUpdate)
	if found {
		t.Fatalf("rule %s unexpectedly found", unlinkedRuleName)
	}
}

// ImageStream in another namespace updating ProfileBundle content; secondary to same-namespace flow.
func TestProfileISTagOtherNs(t *testing.T) {
	if *criticalOnly {
		t.Skip("Skipping non-critical test")
	}
	
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

	removedRuleName := prefixName(pbName, removedRule)
	err, found := f.DoesRuleExist(pb.Namespace, removedRuleName)
	if err != nil {
		t.Fatal(err)
	} else if !found {
		t.Fatalf("expected rule %s to exist", removedRuleName)
	}

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

	if err := f.UpdateImageStreamTag(iSName, modifiedImage, otherNs); err != nil {
		t.Fatalf("failed to update image stream %s: %s", iSName, err)
	}
	modifiedImageDigest, err := f.GetImageStreamUpdatedDigest(iSName, otherNs)
	if err != nil {
		t.Fatalf("failed to get digest for image stream %s: %s", iSName, err)
	}
	if err := f.WaitForDeploymentContentUpdate(pbName, modifiedImageDigest); err != nil {
		t.Fatalf("failed waiting for content to update: %s", err)
	}
	if err := f.AssertProfileBundleMustHaveParsedRules(pbName); err != nil {
		t.Fatal(err)
	}
	err, found = f.DoesRuleExist(pb.Namespace, removedRuleName)
	if err != nil {
		t.Fatal(err)
	} else if found {
		t.Fatalf("rule %s unexpectedly found", removedRuleName)
	}

	profilePostUpdate := &compv1alpha1.Profile{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: pb.Namespace, Name: profileName}, profilePostUpdate); err != nil {
		t.Fatalf("failed to get profile %s", profileName)
	}
	found = framework.IsRuleInProfile(unlinkedRuleName, profilePostUpdate)
	if found {
		t.Fatalf("rule %s unexpectedly found", unlinkedRuleName)
	}
}

// CRITICAL: Parser must restart on bad content and recover when fixed; otherwise one bad image can leave bundle stuck invalid.
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
	if err := f.WaitForProfileBundleStatus(pbName, compv1alpha1.DataStreamValid); err != nil {
		t.Fatal(err)
	}
}

// CRITICAL: Default ocp4 ProfileBundle must be restored after operator reconciliation; otherwise default install is broken.
func TestProfileBundleDefaultIsKept(t *testing.T) {
	f := framework.Global
	var (
		otherImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_baseline")
		bctx       = context.Background()
	)

	ocpPb, err := f.GetReadyProfileBundle("ocp4", f.OperatorNamespace)
	if err != nil {
		t.Fatalf("failed to get ocp4 ProfileBundle: %s", err)
	}

	origImage := ocpPb.Spec.ContentImage

	ocpPbCopy := ocpPb.DeepCopy()
	ocpPbCopy.Spec.ContentImage = otherImage
	ocpPbCopy.Spec.ContentFile = framework.RhcosContentFile
	if updateErr := f.Client.Update(bctx, ocpPbCopy); updateErr != nil {
		t.Fatalf("failed to update default ocp4 profile: %s", err)
	}

	if err := f.WaitForProfileBundleStatus("ocp4", compv1alpha1.DataStreamPending); err != nil {
		t.Fatalf("ocp4 update didn't trigger a PENDING state: %s", err)
	}

	// Now wait for the processing to finish
	if err := f.WaitForProfileBundleStatus("ocp4", compv1alpha1.DataStreamValid); err != nil {
		t.Fatalf("ocp4 update didn't trigger a PENDING state: %s", err)
	}

	// Delete compliance operator pods
	// This will trigger a reconciliation of the profile bundle
	// This is what would happen on an operator update.

	inNs := client.InNamespace(f.OperatorNamespace)
	withLabel := client.MatchingLabels{
		"name": "compliance-operator",
	}
	if err := f.Client.DeleteAllOf(bctx, &corev1.Pod{}, inNs, withLabel); err != nil {
		t.Fatalf("failed to delete compliance-operator pods: %s", err)
	}

	// Wait for the operator deletion to happen
	time.Sleep(framework.RetryInterval)

	err = f.WaitForDeployment("compliance-operator", 1, framework.RetryInterval, framework.Timeout)
	if err != nil {
		t.Fatalf("failed waiting for compliance-operator to come back up: %s", err)
	}

	var lastErr error
	pbkey := types.NamespacedName{Name: "ocp4", Namespace: f.OperatorNamespace}
	timeouterr := wait.Poll(framework.RetryInterval, framework.Timeout, func() (bool, error) {
		pb := &compv1alpha1.ProfileBundle{}
		if lastErr := f.Client.Get(bctx, pbkey, pb); lastErr != nil {
			log.Printf("error getting ocp4 PB. Retrying: %s\n", err)
			return false, nil
		}
		if pb.Spec.ContentImage != origImage {
			log.Printf("ProfileBundle ContentImage not updated yet: Got %s - Expected %s\n", pb.Spec.ContentImage, origImage)
			return false, nil
		}
		log.Printf("ProfileBundle ContentImage up-to-date\n")
		return true, nil
	})
	if lastErr != nil {
		t.Fatalf("failed waiting for ProfileBundle to update: %s", lastErr)
	}
	if timeouterr != nil {
		t.Fatalf("timed out waiting for ProfileBundle to update: %s", timeouterr)
	}

	_, err = f.GetReadyProfileBundle("ocp4", f.OperatorNamespace)
	if err != nil {
		t.Fatalf("error getting valid and up-to-date PB: %s", err)
	}
}