package framework

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
	imagev1 "github.com/openshift/api/image/v1"
	promv1 "github.com/prometheus/prometheus/web/api/v1"
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

// AssertScanHasTotalCheckCounts asserts that the scan has the expected total check counts
func (f *Framework) AssertScanHasTotalCheckCounts(namespace, scanName string) error {
	// check if scan has annotation
	var scan compv1alpha1.ComplianceScan
	key := types.NamespacedName{Namespace: namespace, Name: scanName}
	if err := f.Client.Get(context.Background(), key, &scan); err != nil {
		return err
	}
	if scan.Annotations == nil {
		return fmt.Errorf("expected annotations to be not nil")
	}
	if scan.Annotations[compv1alpha1.ComplianceCheckCountAnnotation] == "" {
		return fmt.Errorf("expected %s to be not empty", compv1alpha1.ComplianceCheckCountAnnotation)
	}

	gotCheckCount, err := strconv.Atoi(scan.Annotations[compv1alpha1.ComplianceCheckCountAnnotation])
	if err != nil {
		return fmt.Errorf("failed to convert %s to int: %w", compv1alpha1.ComplianceCheckCountAnnotation, err)
	}

	var checkList compv1alpha1.ComplianceCheckResultList
	checkListOpts := client.MatchingLabels{
		compv1alpha1.ComplianceScanLabel: scanName,
	}
	if err := f.Client.List(context.TODO(), &checkList, &checkListOpts); err != nil {
		return err
	}

	if gotCheckCount != len(checkList.Items) {
		return fmt.Errorf("expected %s to be %d, got %d instead", compv1alpha1.ComplianceCheckCountAnnotation, len(checkList.Items), gotCheckCount)
	}

	return nil
}

// AssertRuleCheckTypeChangedAnnotationKey asserts that the rule check type changed annotation key exists
func (f *Framework) AssertRuleCheckTypeChangedAnnotationKey(namespace, ruleName, lastCheckType string) error {
	var r compv1alpha1.Rule
	key := types.NamespacedName{Namespace: namespace, Name: ruleName}
	if err := f.Client.Get(context.Background(), key, &r); err != nil {
		return err
	}
	if r.Annotations == nil {
		return fmt.Errorf("expected annotations to be not nil")
	}
	if r.Annotations[compv1alpha1.RuleLastCheckTypeChangedAnnotationKey] != lastCheckType {
		return fmt.Errorf("expected %s to be %s, got %s instead", compv1alpha1.RuleLastCheckTypeChangedAnnotationKey, lastCheckType, r.Annotations[compv1alpha1.RuleLastCheckTypeChangedAnnotationKey])
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

func ProcessErrorOrTimeout(err, timeoutErr error, message string) error {
	// Error in function call
	if err != nil {
		return fmt.Errorf("got error when %s: %w", message, err)
	}
	// Timeout
	if timeoutErr != nil {
		return fmt.Errorf("timed out when %s: %w", message, timeoutErr)
	}
	return nil
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
	timeouterr := wait.Poll(RetryInterval, Timeout, func() (bool, error) {
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
	timeouterr = wait.Poll(RetryInterval, Timeout, func() (bool, error) {
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

func writeToArtifactsDir(dir, scan, pod, container, log string) error {
	logPath := path.Join(dir, fmt.Sprintf("%s_%s_%s.log", scan, pod, container))
	logFile, err := os.Create(logPath)
	if err != nil {
		return err
	}
	// #nosec G307
	defer logFile.Close()
	_, err = io.WriteString(logFile, log)
	if err != nil {
		return err
	}
	return nil
}

func AssertEachMetric(namespace string, expectedMetrics map[string]int) error {
	metricErrs := make([]error, 0)
	metricsOutput, err := getMetricResults(namespace)
	if err != nil {
		return err
	}
	for metric, i := range expectedMetrics {
		err := assertMetric(metricsOutput, metric, i)
		if err != nil {
			metricErrs = append(metricErrs, err)
		}
	}
	if len(metricErrs) > 0 {
		for err := range metricErrs {
			log.Println(err)
		}
		return errors.New("unexpected metrics value")
	}
	return nil
}

func (f *Framework) AssertMetricsEndpointUsesHTTPVersion(endpoint, version string) error {
	ocPath, err := exec.LookPath("oc")
	if err != nil {
		return err
	}

	curlCMD := "curl -i -ks " + endpoint
	// We're just under test.
	// G204 (CWE-78): Subprocess launched with variable (Confidence: HIGH, Severity: MEDIUM)
	// #nosec
	cmd := exec.Command(ocPath,
		"run", "--rm", "-i", "--restart=Never", "--image=registry.fedoraproject.org/fedora-minimal:latest",
		"-n", f.OperatorNamespace, "metrics-test", "--", "bash", "-c", curlCMD,
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error getting output %s", err)
	}
	if !strings.Contains(string(out), version) {
		return fmt.Errorf("metric endpoint is not using %s", version)
	}
	return nil
}

func runOCandGetOutput(arg []string) (string, error) {
	ocPath, err := exec.LookPath("oc")
	if err != nil {
		return "", fmt.Errorf("Failed to find oc binary: %v", err)
	}

	cmd := exec.Command(ocPath, arg...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("Failed to run oc command: %v", err)
	}
	return string(out), nil
}

// createServiceAccount creates a service account
func (f *Framework) SetupRBACForMetricsTest() error {
	_, err := runOCandGetOutput([]string{
		"create", "sa", PromethusTestSA, "-n", f.OperatorNamespace})
	if err != nil {
		return fmt.Errorf("Failed to create service account: %v", err)
	}

	_, err = runOCandGetOutput([]string{
		"adm", "policy", "add-cluster-role-to-user", "cluster-monitoring-view", "-z", PromethusTestSA, "-n", f.OperatorNamespace})
	if err != nil {
		return fmt.Errorf("Failed to add cluster role to user: %v", err)
	}
	return nil
}

// CleanupRBACForMetricsTest deletes the service account
func (f *Framework) CleanUpRBACForMetricsTest() error {
	_, err := runOCandGetOutput([]string{
		"delete", "sa", PromethusTestSA, "-n", f.OperatorNamespace})
	if err != nil {
		return fmt.Errorf("Failed to delete service account: %v", err)
	}
	return nil
}

// WaitForPrometheusMetricTargets retrieves Prometheus metric targets
func (f *Framework) WaitForPrometheusMetricTargets() ([]promv1.Target, error) {
	var metricsTargets []promv1.Target
	var lastErr error

	const prometheusCommand = `
		TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) && 
		{ curl -k -s https://prometheus-k8s.openshift-monitoring.svc.cluster.local:9091/api/v1/targets \
		  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
		  -H "Authorization: Bearer $TOKEN"; }
	`
	namespace := f.OperatorNamespace

	timeouterr := wait.Poll(RetryInterval, Timeout, func() (bool, error) {
		// Clear slice in case of a retry
		metricsTargets = nil

		out, err := runOCandGetOutput([]string{
			"run", "--rm", "-i", "--restart=Never", "--image=registry.fedoraproject.org/fedora:latest",
			"-n", namespace,
			"--overrides={\"spec\": {\"serviceAccountName\": \"" + PromethusTestSA + "\"}}",
			"metrics-test", "--", "bash", "-c", prometheusCommand,
		})

		if err != nil {
			lastErr = fmt.Errorf("error getting output: %v", err)
			log.Printf("%v... retrying\n", lastErr)
			return false, nil
		}

		outTrimmed := trimOutput(string(out))
		if outTrimmed == "" {
			lastErr = fmt.Errorf("empty output from prometheus command")
			log.Printf("%v... retrying\n", lastErr)
			return false, nil
		}

		log.Printf("Metrics output:\n%s\n", outTrimmed)
		var responseData struct {
			Data struct {
				ActiveTargets []promv1.Target `json:"activeTargets"`
			} `json:"data"`
		}
		err = json.Unmarshal([]byte(outTrimmed), &responseData)
		if err != nil {
			lastErr = fmt.Errorf("error unmarshalling json: %v", err)
			log.Printf("%v... retrying\n", lastErr)
			return false, nil
		}

		// Filter metrics for the specified namespace
		for _, metricsTarget := range responseData.Data.ActiveTargets {
			if metricsTarget.Labels != nil &&
				metricContainsLabel(metricsTarget, "namespace", namespace) &&
				(metricContainsLabel(metricsTarget, "endpoint", "metrics") ||
					metricContainsLabel(metricsTarget, "endpoint", "metrics-co")) {

				metricsTargets = append(metricsTargets, metricsTarget)
			}
		}

		// If we find at least one matching target, consider this a success.
		if len(metricsTargets) == 0 {
			lastErr = fmt.Errorf("no matching metrics found for namespace %q", namespace)
			log.Printf("%v... retrying\n", lastErr)
			return false, nil
		}

		// Successfully retrieved and filtered targets, stop polling
		return true, nil
	})

	// If Poll returned an error, it means we timed out
	if timeouterr != nil {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, timeouterr
	}

	return metricsTargets, nil
}

// function to check a label value in a metric match certain value
func metricContainsLabel(metricTarget promv1.Target, labelName string, labelValue string) bool {
	if metricTarget.Labels != nil {
		for _, label := range metricTarget.Labels {
			if label.Name == labelName && label.Value == labelValue {
				return true
			}
		}
	}
	return false
}

func trimOutput(out string) string {
	startIndex := strings.Index(out, `{"status":"`)
	if startIndex == -1 {
		return ""
	}

	endIndex := strings.LastIndex(out, "}")
	if endIndex == -1 {
		return ""
	}

	return out[startIndex : endIndex+1]
}

// assertServiceMonitoringMetricsTarget checks if the specified metrics are up
func (f *Framework) AssertServiceMonitoringMetricsTarget(metrics []promv1.Target, expectedTargetsCount int) error {
	// make sure we have required metrics
	if len(metrics) != expectedTargetsCount {
		return fmt.Errorf("Expected %d metrics, got %d", expectedTargetsCount, len(metrics))
	}

	for _, metric := range metrics {
		if metric.Health != "up" {
			return fmt.Errorf("Metric %s is not up. LastError: %s", metric.Labels, metric.LastError)
		} else {
			log.Printf("Metric instance %s is up. LastScrape: %s", metric.Labels, metric.LastScrape)
		}
	}
	return nil
}

func assertMetric(content, metric string, expected int) error {
	val, err := parseMetric(content, metric)
	if err != nil {
		return err
	}
	if val != expected {
		return fmt.Errorf("expected %v for counter %s, got %v", expected, metric, val)
	}
	return nil
}

// parseMetrics checks the contents for the number of metrics as a substring
// and returns the number of occurrences along with any errors.
func parseMetric(content, metric string) (int, error) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, metric) {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				return 0, fmt.Errorf("invalid metric")
			}
			i, err := strconv.Atoi(fields[1])
			if err != nil {
				return 0, fmt.Errorf("invalid metric value")
			}
			return i, nil
		}
	}
	return 0, nil
}

func getMetricResults(namespace string) (string, error) {
	ocPath, err := exec.LookPath("oc")
	if err != nil {
		return "", err
	}
	// We're just under test.
	// G204 (CWE-78): Subprocess launched with variable (Confidence: HIGH, Severity: MEDIUM)
	// #nosec
	cmd := exec.Command(ocPath,
		"run", "--rm", "-i", "--restart=Never", "--image=registry.fedoraproject.org/fedora-minimal:latest",
		"-n", namespace, "metrics-test", "--", "bash", "-c",
		getTestMetricsCMD(namespace),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("error getting output %s", err)
	}
	log.Printf("metrics output:\n%s\n", string(out))
	return string(out), nil
}

func getTestMetricsCMD(namespace string) string {
	var curlCMD = "curl -ks -H \"Authorization: Bearer `cat /var/run/secrets/kubernetes.io/serviceaccount/token`\" "
	return curlCMD + fmt.Sprintf("https://metrics.%s.svc:8585/metrics-co", namespace)
}

func GetPoolNodeRoleSelector() map[string]string {
	return utils.GetNodeRoleSelector(TestPoolName)
}

// GetDefaultStorageClassProvisioner retrieves the provisioner from the default storage class
func (f *Framework) GetDefaultStorageClassProvisioner() (string, error) {
	var scList unstructured.UnstructuredList
	scList.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "storage.k8s.io",
		Version: "v1",
		Kind:    "StorageClassList",
	})

	if err := f.Client.List(context.TODO(), &scList); err != nil {
		return "", fmt.Errorf("failed to list storage classes: %w", err)
	}

	for _, sc := range scList.Items {
		annotations := sc.GetAnnotations()
		if annotations != nil {
			if isDefault, ok := annotations["storageclass.kubernetes.io/is-default-class"]; ok && isDefault == "true" {
				provisioner, found, err := unstructured.NestedString(sc.Object, "provisioner")
				if err != nil {
					return "", fmt.Errorf("failed to get provisioner from storage class: %w", err)
				}
				if !found {
					return "", fmt.Errorf("provisioner field not found in default storage class")
				}
				return provisioner, nil
			}
		}
	}

	return "", fmt.Errorf("no default storage class found in the cluster")
}

// CreateCustomStorageClass creates a custom StorageClass object
func (f *Framework) CreateCustomStorageClass(name, provisioner string) *unstructured.Unstructured {
	sc := &unstructured.Unstructured{}
	sc.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "storage.k8s.io",
		Version: "v1",
		Kind:    "StorageClass",
	})
	sc.SetName(name)
	unstructured.SetNestedField(sc.Object, provisioner, "provisioner")
	return sc
}

// AssertScanPVCHasStorageConfig verifies that the PVC for a scan has the expected storage configuration
func (f *Framework) AssertScanPVCHasStorageConfig(scanName, namespace, expectedStorageClassName string, expectedAccessMode corev1.PersistentVolumeAccessMode) error {
	// List all PVCs in the namespace
	pvcList := &corev1.PersistentVolumeClaimList{}
	listOpts := &client.ListOptions{
		Namespace: namespace,
	}
	if err := f.Client.List(context.TODO(), pvcList, listOpts); err != nil {
		return fmt.Errorf("failed to list PVCs: %w", err)
	}

	// Find the PVC for the scan
	var scanPVC *corev1.PersistentVolumeClaim
	for i := range pvcList.Items {
		pvc := &pvcList.Items[i]
		// Check if this PVC belongs to our scan
		if pvc.Labels != nil {
			if scanLabel, ok := pvc.Labels[compv1alpha1.ComplianceScanLabel]; ok && scanLabel == scanName {
				scanPVC = pvc
				break
			}
		}
		// Alternative: check if the PVC name contains our scan name
		if strings.Contains(pvc.Name, scanName) {
			scanPVC = pvc
			break
		}
	}

	if scanPVC == nil {
		return fmt.Errorf("no PVC found for scan %s", scanName)
	}

	// Verify PVC has the correct storageClassName
	if scanPVC.Spec.StorageClassName == nil {
		return fmt.Errorf("PVC %s has nil storageClassName", scanPVC.Name)
	}
	if *scanPVC.Spec.StorageClassName != expectedStorageClassName {
		return fmt.Errorf("expected PVC storageClassName to be %s, got %s", expectedStorageClassName, *scanPVC.Spec.StorageClassName)
	}

	// Verify PVC has the correct accessModes
	if len(scanPVC.Spec.AccessModes) == 0 {
		return fmt.Errorf("PVC %s has no access modes", scanPVC.Name)
	}

	found := false
	for _, mode := range scanPVC.Spec.AccessModes {
		if mode == expectedAccessMode {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("expected PVC to have access mode %s, got %v", expectedAccessMode, scanPVC.Spec.AccessModes)
	}

	log.Printf("Successfully verified PVC %s has storageClassName=%s and accessModes=%v\n",
		scanPVC.Name, *scanPVC.Spec.StorageClassName, scanPVC.Spec.AccessModes)

	return nil
}
