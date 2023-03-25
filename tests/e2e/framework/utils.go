package framework

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"testing"
	"time"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
	imagev1 "github.com/openshift/api/image/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (f *Framework) AssertMustHaveParsedProfiles(pbName, productType, productName string) error {
	var l compv1alpha1.ProfileList
	o := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(map[string]string{
			compv1alpha1.ProfileBundleOwnerLabel: pbName,
		}),
	}
	if err := f.Client.List(context.TODO(), &l, o); err != nil {
		return err
	}
	if len(l.Items) <= 0 {
		return fmt.Errorf("failed to get profiles from ProfileBundle %s. Expected at least one but got %d", pbName, len(l.Items))
	}

	for _, p := range l.Items {
		if p.Annotations[compv1alpha1.ProductTypeAnnotation] != productType {
			return fmt.Errorf("expected %s to be %s, got %s instead", compv1alpha1.ProductTypeAnnotation, productType, p.Annotations[compv1alpha1.ProductTypeAnnotation])
		}

		if p.Annotations[compv1alpha1.ProductAnnotation] != productName {
			return fmt.Errorf("expected %s to be %s, got %s instead", compv1alpha1.ProductAnnotation, productName, p.Annotations[compv1alpha1.ProductAnnotation])
		}
	}
	return nil
}

func (f *Framework) DoesRuleExist(namespace, ruleName string) (error, bool) {
	err, found := f.DoesObjectExist("Rule", namespace, ruleName)
	if err != nil {
		return fmt.Errorf("failed to get rule %s", ruleName), found
	}
	return err, found
}

func (f *Framework) DoesObjectExist(kind, namespace, name string) (error, bool) {
	obj := unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   compv1alpha1.SchemeGroupVersion.Group,
		Version: compv1alpha1.SchemeGroupVersion.Version,
		Kind:    kind,
	})

	key := types.NamespacedName{Namespace: namespace, Name: name}
	err := f.Client.Get(context.TODO(), key, &obj)
	if apierrors.IsNotFound(err) {
		return nil, false
	} else if err == nil {
		return nil, true
	}

	return err, false
}

func IsRuleInProfile(ruleName string, profile *compv1alpha1.Profile) bool {
	for _, ref := range profile.Rules {
		if string(ref) == ruleName {
			return true
		}
	}
	return false
}

func (f *Framework) AssertProfileBundleMustHaveParsedRules(pbName string) error {
	var r compv1alpha1.RuleList
	o := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(map[string]string{
			compv1alpha1.ProfileBundleOwnerLabel: pbName,
		}),
	}
	if err := f.Client.List(context.TODO(), &r, o); err != nil {
		return fmt.Errorf("failed to get rule list from ProfileBundle %s: %w", pbName, err)
	}
	if len(r.Items) <= 0 {
		return fmt.Errorf("rules were not parsed from the ProfileBundle %s. Expected more than one, got %d", pbName, len(r.Items))
	}
	return nil
}

func GetObjNameFromTest(t *testing.T) string {
	fullTestName := t.Name()
	regexForCapitals := regexp.MustCompile(`[A-Z]`)

	testNameInitIndex := strings.LastIndex(fullTestName, "/") + 1

	// Remove test prefix
	testName := fullTestName[testNameInitIndex:]

	// convert capitals to lower case letters with hyphens prepended
	hyphenedTestName := regexForCapitals.ReplaceAllStringFunc(
		testName,
		func(currentMatch string) string {
			return "-" + strings.ToLower(currentMatch)
		})
	// remove double hyphens
	testNameNoDoubleHyphens := strings.ReplaceAll(hyphenedTestName, "--", "-")
	// Remove leading and trailing hyphens
	return strings.Trim(testNameNoDoubleHyphens, "-")
}

func (f *Framework) UpdateImageStreamTag(iSName, imagePath, namespace string) error {
	s := &imagev1.ImageStream{}
	key := types.NamespacedName{Name: iSName, Namespace: namespace}
	if err := f.Client.Get(context.TODO(), key, s); err != nil {
		return err
	}
	c := s.DeepCopy()
	// Updated tracked image reference
	c.Spec.Tags[0].From.Name = imagePath
	return f.Client.Update(context.TODO(), c)
}

func (f *Framework) GetImageStreamUpdatedDigest(iSName, namespace string) (string, error) {
	stream := &imagev1.ImageStream{}
	tagItemNum := 0
	key := types.NamespacedName{Name: iSName, Namespace: namespace}
	for tagItemNum < 2 {
		if err := f.Client.Get(context.TODO(), key, stream); err != nil {
			return "", err
		}
		tagItemNum = len(stream.Status.Tags[0].Items)
		time.Sleep(2 * time.Second)
	}

	// Last tag item is at index 0
	imgDigest := stream.Status.Tags[0].Items[0].Image
	return imgDigest, nil
}

func (f *Framework) WaitForDeploymentContentUpdate(pbName, imgDigest string) error {
	lo := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(map[string]string{
			"profile-bundle": pbName,
			"workload":       "profileparser",
		}),
	}

	var depls appsv1.DeploymentList
	var lastErr error
	timeouterr := wait.Poll(retryInterval, timeout, func() (bool, error) {
		lastErr = f.Client.List(context.TODO(), &depls, lo)
		if lastErr != nil {
			log.Printf("failed getting deployment list: %s... retrying\n", lastErr)
			return false, nil
		}
		depl := depls.Items[0]
		currentImg := depl.Spec.Template.Spec.InitContainers[0].Image
		// The image will have a different path, but the digest should be the same
		if !strings.HasSuffix(currentImg, imgDigest) {
			log.Println("content image isn't up-to-date... retrying")
			return false, nil
		}
		return true, nil
	})
	// Error in function call
	if lastErr != nil {
		return lastErr
	}
	// Timeout
	if timeouterr != nil {
		return timeouterr
	}

	log.Printf("profile parser deployment updated\n")

	var pods corev1.PodList
	timeouterr = wait.Poll(retryInterval, timeout, func() (bool, error) {
		lastErr = f.Client.List(context.TODO(), &pods, lo)
		if lastErr != nil {
			log.Printf("failed to list pods: %s... retrying", lastErr)
			return false, nil
		}

		// Deployment updates will trigger a rolling update, so we might have
		// more than one pod. We only care about the newest
		pod := utils.FindNewestPod(pods.Items)

		currentImg := pod.Spec.InitContainers[0].Image
		if !strings.HasSuffix(currentImg, imgDigest) {
			log.Println("content image isn't up-to-date... retrying")
			return false, nil
		}
		if len(pod.Status.InitContainerStatuses) != 2 {
			log.Println("content parsing in progress... retrying")
			return false, nil
		}

		// The profileparser will take time, so we know it'll be index 1
		ppStatus := pod.Status.InitContainerStatuses[1]
		if !ppStatus.Ready {
			log.Println("container not ready... retrying")
			return false, nil
		}
		return true, nil
	})
	// Error in function call
	if lastErr != nil {
		return lastErr
	}
	// Timeout
	if timeouterr != nil {
		return timeouterr
	}
	log.Println("profile parser deployment done")
	return nil
}

func (f *Framework) CreateImageStream(iSName, namespace, imgPath string) (*imagev1.ImageStream, error) {
	stream := &imagev1.ImageStream{
		TypeMeta:   metav1.TypeMeta{APIVersion: imagev1.SchemeGroupVersion.String(), Kind: "ImageStream"},
		ObjectMeta: metav1.ObjectMeta{Name: iSName, Namespace: namespace},
		Spec: imagev1.ImageStreamSpec{
			Tags: []imagev1.TagReference{
				{
					Name: "latest",
					From: &corev1.ObjectReference{
						Kind: "DockerImage",
						Name: imgPath,
					},
					ReferencePolicy: imagev1.TagReferencePolicy{
						Type: imagev1.LocalTagReferencePolicy,
					},
				},
			},
		},
	}
	err := f.Client.Create(context.TODO(), stream, nil)
	return stream, err
}