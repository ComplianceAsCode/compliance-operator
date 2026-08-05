package framework

import (
	"bufio"
	"context"
	"encoding/base64"
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

	"golang.org/x/mod/semver"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
	configv1 "github.com/openshift/api/config/v1"
	imagev1 "github.com/openshift/api/image/v1"
	tlspkg "github.com/openshift/controller-runtime-common/pkg/tls"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
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

// PrometheusTarget represents a Prometheus scrape target from the /api/v1/targets endpoint.
// This is a minimal version of prometheus/web/api/v1.Target to avoid pulling in test dependencies.
type PrometheusTarget struct {
	Labels             map[string]string `json:"labels"`
	DiscoveredLabels   map[string]string `json:"discoveredLabels"`
	ScrapePool         string            `json:"scrapePool"`
	ScrapeURL          string            `json:"scrapeUrl"`
	GlobalURL          string            `json:"globalUrl"`
	LastError          string            `json:"lastError"`
	LastScrape         time.Time         `json:"lastScrape"`
	LastScrapeDuration float64           `json:"lastScrapeDuration"`
	Health             string            `json:"health"`
	ScrapeInterval     string            `json:"scrapeInterval"`
	ScrapeTimeout      string            `json:"scrapeTimeout"`
}

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
		for _, err := range metricErrs {
			log.Println(err)
		}
		// Dump the full metrics payload only on failure, to aid debugging without
		// spamming the log with the whole endpoint on every successful assertion.
		log.Printf("metrics output:\n%s\n", metricsOutput)
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
		"-n", f.OperatorNamespace, fmt.Sprintf("metrics-test-%d", time.Now().UnixNano()), "--", "bash", "-c", curlCMD,
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

func (f *Framework) SetScanSettingSuspend(scanSettingName string, suspend bool) error {
	ss := &compv1alpha1.ScanSetting{}
	key := types.NamespacedName{Name: scanSettingName, Namespace: f.OperatorNamespace}
	if err := f.Client.Get(context.TODO(), key, ss); err != nil {
		return err
	}
	updated := ss.DeepCopy()
	updated.Suspend = suspend
	return f.Client.Update(context.TODO(), updated)
}

func (f *Framework) GetCronJobLastSuccessfulTime(cronJobName string) (string, error) {
	job := &batchv1.CronJob{}
	key := types.NamespacedName{Name: cronJobName, Namespace: f.OperatorNamespace}
	if err := f.Client.Get(context.TODO(), key, job); err != nil {
		return "", err
	}
	if job.Status.LastSuccessfulTime == nil {
		return "", nil
	}
	return job.Status.LastSuccessfulTime.UTC().Format(time.RFC3339Nano), nil
}

// WaitForCronJobLastSuccessfulTimeChanged polls until CronJob status.lastSuccessfulTime is set and
// differs from previousValue. Pass previousValue="" to wait for the first successful time.
// Kubernetes does not clear lastSuccessfulTime on suspend/resume, so callers that need a post-resume
// run must wait for a new timestamp rather than any non-empty value.
func (f *Framework) WaitForCronJobLastSuccessfulTimeChanged(cronJobName, previousValue string, timeout time.Duration) (string, error) {
	lastSuccessfulTime := ""
	err := wait.Poll(RetryInterval, timeout, func() (bool, error) {
		current, err := f.GetCronJobLastSuccessfulTime(cronJobName)
		if err != nil {
			if apierrors.IsNotFound(err) {
				log.Printf("waiting for availability of %s CronJob\n", cronJobName)
			} else {
				log.Printf("Retrying. Got error getting CronJob %s lastSuccessfulTime: %v\n", cronJobName, err)
			}
			return false, nil
		}
		if current == "" || current == previousValue {
			return false, nil
		}
		lastSuccessfulTime = current
		return true, nil
	})
	if err != nil {
		return "", err
	}
	return lastSuccessfulTime, nil
}

func runOCandGetOutput(arg []string) (string, error) {
	ocPath, err := exec.LookPath("oc")
	if err != nil {
		return "", fmt.Errorf("Failed to find oc binary: %v", err)
	}

	cmd := exec.Command(ocPath, arg...)
	out, err := cmd.CombinedOutput()
	outStr := string(out)
	if err != nil {
		return outStr, fmt.Errorf("Failed to run oc command: %v", err)
	}
	return outStr, nil
}

const openshiftMonitoringNamespace = "openshift-monitoring"

// ErrAlertManagerRBACUnavailable is returned by SetupRBACForMetricsTest when the AlertManager
// RoleBinding cannot be created (e.g. no suitable Role in openshift-monitoring). Callers may skip.
var ErrAlertManagerRBACUnavailable = errors.New("AlertManager RBAC unavailable")

// alertManagerRoleNames: Role names in openshift-monitoring for AlertManager API access (view first, then edit).
var alertManagerRoleNames = []string{"monitoring-alertmanager-view", "monitoring-alertmanager-edit"}

// SetupRBACForMetricsTest creates a SA and binds cluster-monitoring-view plus an AlertManager Role in openshift-monitoring (view or edit).
// No custom ClusterRole/Role is created.
func (f *Framework) SetupRBACForMetricsTest() error {
	_, err := runOCandGetOutput([]string{
		"create", "sa", PrometheusTestSA, "-n", f.OperatorNamespace})
	if err != nil {
		return fmt.Errorf("Failed to create service account: %v", err)
	}

	_, err = runOCandGetOutput([]string{
		"adm", "policy", "add-cluster-role-to-user", "cluster-monitoring-view", "-z", PrometheusTestSA, "-n", f.OperatorNamespace})
	if err != nil {
		return fmt.Errorf("Failed to add cluster-monitoring-view role: %v", err)
	}

	roleBindingName := "compliance-e2e-" + PrometheusTestSA + "-alertmanager-view"
	var lastErr error
	var lastOut string
	for _, roleName := range alertManagerRoleNames {
		out, createErr := runOCandGetOutput([]string{
			"create", "rolebinding", roleBindingName,
			"--role=" + roleName,
			"--serviceaccount=" + f.OperatorNamespace + ":" + PrometheusTestSA,
			"-n", openshiftMonitoringNamespace,
		})
		if createErr == nil {
			return nil
		}
		lastErr = createErr
		lastOut = out
	}
	errMsg := fmt.Sprintf("tried roles %v in %s: %v", alertManagerRoleNames, openshiftMonitoringNamespace, lastErr)
	if strings.TrimSpace(lastOut) != "" {
		errMsg += "; oc output: " + strings.TrimSpace(lastOut)
	}
	return fmt.Errorf("%w (%s)", ErrAlertManagerRBACUnavailable, errMsg)
}

// CleanUpRBACForMetricsTest removes the cluster role binding, the rolebinding in openshift-monitoring, and the service account.
func (f *Framework) CleanUpRBACForMetricsTest() error {
	runOCandGetOutput([]string{
		"adm", "policy", "remove-cluster-role-from-user", "cluster-monitoring-view", "-z", PrometheusTestSA, "-n", f.OperatorNamespace})

	roleBindingName := "compliance-e2e-" + PrometheusTestSA + "-alertmanager-view"
	runOCandGetOutput([]string{
		"delete", "rolebinding", roleBindingName, "-n", openshiftMonitoringNamespace, "--ignore-not-found=true"})

	_, err := runOCandGetOutput([]string{
		"delete", "sa", PrometheusTestSA, "-n", f.OperatorNamespace})
	if err != nil {
		return fmt.Errorf("Failed to delete service account: %v", err)
	}
	return nil
}

// WaitForPrometheusMetricTargets retrieves Prometheus metric targets
func (f *Framework) WaitForPrometheusMetricTargets() ([]PrometheusTarget, error) {
	var metricsTargets []PrometheusTarget
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

		podOverrides, err := generatePodOverrides(prometheusCommand)
		if err != nil {
			return false, err
		}

		out, err := runOCandGetOutput([]string{
			"run", "--rm", "-i", "--restart=Never", "--image=" + FedoraTestImage,
			"-n", namespace,
			"--overrides=" + podOverrides,
			"metrics-test",
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
				ActiveTargets []PrometheusTarget `json:"activeTargets"`
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
			if len(metricsTarget.Labels) > 0 &&
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
func metricContainsLabel(metricTarget PrometheusTarget, labelName string, labelValue string) bool {
	if len(metricTarget.Labels) > 0 {
		return metricTarget.Labels[labelName] == labelValue
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
func (f *Framework) AssertServiceMonitoringMetricsTarget(metrics []PrometheusTarget, expectedTargetsCount int) error {
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
		"-n", namespace, fmt.Sprintf("metrics-test-%d", time.Now().UnixNano()), "--", "bash", "-c",
		getTestMetricsCMD(namespace),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("error getting output %s", err)
	}
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
func (f *Framework) CreateCustomStorageClass(name, provisioner string) (*unstructured.Unstructured, error) {
	sc := &unstructured.Unstructured{}
	sc.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "storage.k8s.io",
		Version: "v1",
		Kind:    "StorageClass",
	})
	sc.SetName(name)
	if err := unstructured.SetNestedField(sc.Object, provisioner, "provisioner"); err != nil {
		return nil, fmt.Errorf("failed to set provisioner field: %w", err)
	}
	return sc, nil
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

// generatePodOverrides returns JSON pod spec overrides for running a command in a temporary pod
// (e.g. for metrics or AlertManager API calls). command is the bash -c argument.
func generatePodOverrides(command string) (string, error) {
	m := map[string]interface{}{
		"spec": map[string]interface{}{
			"serviceAccountName": PrometheusTestSA,
			"securityContext": map[string]interface{}{
				"runAsNonRoot":   true,
				"seccompProfile": map[string]interface{}{"type": "RuntimeDefault"},
			},
			"containers": []map[string]interface{}{
				{
					"name":    "test",
					"image":   FedoraTestImage,
					"command": []string{"bash", "-c", command},
					"securityContext": map[string]interface{}{
						"allowPrivilegeEscalation": false,
						"runAsNonRoot":             true,
						"capabilities":             map[string]interface{}{"drop": []string{"ALL"}},
						"seccompProfile":           map[string]interface{}{"type": "RuntimeDefault"},
					},
				},
			},
		},
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("marshal pod overrides: %w", err)
	}
	return string(b), nil
}

// AssertAlertManagerAlertExists checks that an alert exists in AlertManager with the specified
// label name and description string.
func (f *Framework) AssertAlertManagerAlertExists(labelName, expectedDescription string, timeout time.Duration) error {
	apiVersion, err := f.getAlertManagerAPIVersion()
	if err != nil {
		return fmt.Errorf("failed to determine AlertManager API version: %w", err)
	}

	alertManagerURL, err := f.getAlertManagerURL()
	if err != nil {
		return fmt.Errorf("failed to get AlertManager URL: %w", err)
	}

	const alertManagerCommand = `
		TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) && 
		{ curl -k -s -w "\nHTTP_CODE:%%{http_code}" https://%s/api/%s/alerts \
		  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
		  -H "Authorization: Bearer $TOKEN"; }
	`
	command := fmt.Sprintf(alertManagerCommand, alertManagerURL, apiVersion)
	namespace := f.OperatorNamespace

	var lastErr error
	timeouterr := wait.Poll(RetryInterval, timeout, func() (bool, error) {
		podOverrides, err := generatePodOverrides(command)
		if err != nil {
			return false, err
		}

		out, err := runOCandGetOutput([]string{
			"run", "--rm", "-i", "--restart=Never", "--image=" + FedoraTestImage,
			"-n", namespace,
			"--overrides=" + podOverrides,
			"alertmanager-test",
		})

		if err != nil {
			lastErr = fmt.Errorf("error getting AlertManager output: %v", err)
			ocOut := out
			if len(ocOut) > 600 {
				ocOut = ocOut[:600] + "...[truncated]"
			}
			return false, nil
		}

		outStr := string(out)
		outTrimmed := trimAlertManagerOutput(outStr)
		if outTrimmed == "" {
			lastErr = fmt.Errorf("empty output from AlertManager command")
			log.Printf("%v... retrying\n", lastErr)
			return false, nil
		}

		// Parse the AlertManager API response
		// For v1 API, alerts are in data.alerts array
		// For v2 API, alerts are directly in an array
		var alerts []struct {
			Labels      map[string]string      `json:"labels"`
			Annotations map[string]string      `json:"annotations"`
			Status      struct{ State string } `json:"status"`
		}

		// Try parsing as v2 format first (direct array)
		err = json.Unmarshal([]byte(outTrimmed), &alerts)
		if err != nil {
			// Try parsing as v1 format (wrapped in data object)
			var v1Response struct {
				Data struct {
					Alerts []struct {
						Labels      map[string]string      `json:"labels"`
						Annotations map[string]string      `json:"annotations"`
						Status      struct{ State string } `json:"status"`
					} `json:"alerts"`
				} `json:"data"`
			}
			if err2 := json.Unmarshal([]byte(outTrimmed), &v1Response); err2 == nil {
				alerts = v1Response.Data.Alerts
			} else {
				lastErr = fmt.Errorf("error unmarshalling AlertManager JSON: %v", err)
				log.Printf("%v... retrying\n", lastErr)
				return false, nil
			}
		}

		// Check if any alert has the expected label name and description
		for _, alert := range alerts {
			if alert.Labels != nil {
				// Check if the alert has a label with value matching the suite name
				if nameValue, found := alert.Labels["name"]; found && nameValue == labelName {
					if alert.Annotations != nil {
						description, found := alert.Annotations["description"]
						if found && strings.Contains(description, expectedDescription) {
							return true, nil
						}
					}
				}
			}
		}

		lastErr = fmt.Errorf("alert with label name=%s and description containing '%s' not found in AlertManager", labelName, expectedDescription)
		log.Printf("%v... retrying\n", lastErr)
		return false, nil
	})

	if timeouterr != nil {
		if lastErr != nil {
			return fmt.Errorf("failed to find alert in AlertManager: %w", lastErr)
		}
		return fmt.Errorf("timed out waiting for alert in AlertManager: %w", timeouterr)
	}

	return nil
}

// trimAlertManagerOutput extracts JSON from AlertManager API output. The command appends
// "\nHTTP_CODE:NNN" (possibly followed by more text like "pod ... deleted"). We require
// HTTP 200 before returning body; otherwise return "" so callers retry. Uses bracket/brace
// counting to find the matching closing delimiter so nested or in-string '['/']' do not break parsing.
func trimAlertManagerOutput(out string) string {
	// Split on HTTP_CODE: body is everything before it, status code is the digits immediately after "HTTP_CODE:"
	body := out
	if idx := strings.Index(out, "HTTP_CODE:"); idx != -1 {
		body = out[:idx]
		codeStr := out[idx+len("HTTP_CODE:"):]
		// Code may be "200" or "200pod \"...\" deleted" — take only leading digits
		var digits strings.Builder
		for _, r := range codeStr {
			if r >= '0' && r <= '9' {
				digits.WriteRune(r)
			} else {
				break
			}
		}
		if digits.Len() == 0 {
			return ""
		}
		if code, err := strconv.Atoi(digits.String()); err != nil || code != 200 {
			return ""
		}
	}

	// Find JSON start: first '[' or v1 API object
	jsonStart := strings.Index(body, "[")
	if jsonStart == -1 {
		dataStart := strings.Index(body, `{"data"`)
		if dataStart != -1 {
			jsonStart = dataStart
		} else {
			return ""
		}
	}

	if jsonStart < len(body) && body[jsonStart] == '[' {
		// Find matching ']' by bracket count so nested or in-content '['/']' are handled
		depth := 0
		for i := jsonStart; i < len(body); i++ {
			switch body[i] {
			case '[':
				depth++
			case ']':
				depth--
				if depth == 0 {
					return body[jsonStart : i+1]
				}
			}
		}
		return ""
	}
	// v1 API: object starting with {"data"; find matching '}'
	depth := 0
	for i := jsonStart; i < len(body); i++ {
		switch body[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return body[jsonStart : i+1]
			}
		}
	}
	return ""
}

// getAlertManagerAPIVersion determines the AlertManager API version based on cluster version
// Returns "v1" for OCP 4.x < 4.17, "v2" for OCP >= 4.17 and OCP 5+
func (f *Framework) getAlertManagerAPIVersion() (string, error) {
	version, err := runOCandGetOutput([]string{
		"get", "clusterversion/version", "-ojsonpath={.status.desired.version}",
	})
	if err != nil {
		return "", fmt.Errorf("failed to get cluster version: %w", err)
	}

	version = strings.TrimSpace(version)
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid version format: %s", version)
	}

	majorStr := parts[0]
	major, err := strconv.Atoi(majorStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse major version: %w", err)
	}
	minorStr := parts[1]
	minor, err := strconv.Atoi(minorStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse minor version: %w", err)
	}

	if major >= 5 {
		return "v2", nil
	}
	if major == 4 && minor >= 17 {
		return "v2", nil
	}
	if major == 4 && minor < 17 {
		return "v1", nil
	}

	return "", fmt.Errorf("unknown version %s.%s", majorStr, minorStr)
}

// getAlertManagerURL gets the AlertManager route URL
func (f *Framework) getAlertManagerURL() (string, error) {
	// Try to get route first
	route, err := runOCandGetOutput([]string{
		"get", "route", "alertmanager-main", "-n", "openshift-monitoring", "-o=jsonpath={.spec.host}",
	})
	if err == nil && strings.TrimSpace(route) != "" {
		return strings.TrimSpace(route), nil
	}

	// Fallback to service URL
	return "alertmanager-main.openshift-monitoring.svc.cluster.local:9093", nil
}

// GetClusterAPIServer fetches the APIServer "cluster" resource.
func (f *Framework) GetClusterAPIServer() (*configv1.APIServer, error) {
	apiServer := &configv1.APIServer{}
	key := types.NamespacedName{Name: "cluster"}
	if err := f.Client.Get(context.TODO(), key, apiServer); err != nil {
		return nil, fmt.Errorf("failed to get APIServer cluster resource: %w", err)
	}
	return apiServer, nil
}

// GetExpectedMinTLSVersion returns the expected minimum TLS version string
// (e.g., "TLSv1.2", "TLSv1.3") for the metrics endpoint based on the
// cluster's APIServer TLS configuration and adherence policy.
func (f *Framework) GetExpectedMinTLSVersion(apiServer *configv1.APIServer) string {
	profile := extractTLSProfileForTest(apiServer)
	spec, err := tlspkg.GetTLSProfileSpec(profile)
	if err != nil {
		// Fall back to Intermediate defaults if profile resolution fails.
		spec = *configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
	}
	switch spec.MinTLSVersion {
	case configv1.VersionTLS10:
		return "TLSv1.0"
	case configv1.VersionTLS11:
		return "TLSv1.1"
	case configv1.VersionTLS12:
		return "TLSv1.2"
	case configv1.VersionTLS13:
		return "TLSv1.3"
	default:
		return "TLSv1.2"
	}
}

// tlsVersionNumber maps a TLS version string (e.g. "TLSv1.2") to a numeric
// value for comparison. Higher values mean newer TLS versions.
var tlsVersionNumber = map[string]int{
	"TLSv1.0": 10,
	"TLSv1.1": 11,
	"TLSv1.2": 12,
	"TLSv1.3": 13,
}

// parseTLSVersionFromCurlOutput extracts the TLS version string from curl
// verbose output containing an "SSL connection using TLSvX.Y" line.
func parseTLSVersionFromCurlOutput(output string) string {
	re := regexp.MustCompile(`TLSv1\.[0-3]`)
	return re.FindString(output)
}

// tlsVersionAtLeast returns true if actual >= minimum using the TLS version
// ordering. Both arguments should be strings like "TLSv1.2".
func tlsVersionAtLeast(actual, minimum string) bool {
	a, aOK := tlsVersionNumber[actual]
	m, mOK := tlsVersionNumber[minimum]
	if !aOK || !mOK {
		return false
	}
	return a >= m
}

// AssertMetricsEndpointMinTLSVersion uses curl to connect to the metrics
// endpoint and verifies the negotiated TLS version is at least the expected
// minimum. The server may negotiate a higher version than the minimum (e.g.
// TLS 1.3 when the minimum is 1.2), which is correct behavior.
func (f *Framework) AssertMetricsEndpointMinTLSVersion(expectedMinTLSVersion string) error {
	endpoint := fmt.Sprintf("https://metrics.%s.svc:8585/metrics-co", f.OperatorNamespace)
	curlCMD := fmt.Sprintf("curl -vks %s 2>&1 | grep 'SSL connection'", endpoint)

	ocPath, err := exec.LookPath("oc")
	if err != nil {
		return fmt.Errorf("oc not found: %w", err)
	}

	var lastErr error
	timeouterr := wait.Poll(RetryInterval, Timeout, func() (bool, error) {
		// #nosec G204
		cmd := exec.Command(ocPath,
			"run", "--rm", "-i", "--restart=Never",
			"--image=registry.fedoraproject.org/fedora-minimal:latest",
			"-n", f.OperatorNamespace, "tls-version-test",
			"--", "bash", "-c", curlCMD,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			lastErr = fmt.Errorf("curl command failed: %v, output: %s", err, string(out))
			log.Printf("%v... retrying\n", lastErr)
			return false, nil
		}

		output := string(out)
		actual := parseTLSVersionFromCurlOutput(output)
		if actual == "" {
			lastErr = fmt.Errorf("could not parse TLS version from output: %s", output)
			log.Printf("%v... retrying\n", lastErr)
			return false, nil
		}
		if !tlsVersionAtLeast(actual, expectedMinTLSVersion) {
			lastErr = fmt.Errorf("negotiated TLS version %s is below minimum %s", actual, expectedMinTLSVersion)
			log.Printf("%v... retrying\n", lastErr)
			return false, nil
		}
		log.Printf("metrics endpoint using %s (minimum: %s)\n", actual, expectedMinTLSVersion)
		return true, nil
	})
	if timeouterr != nil {
		if lastErr != nil {
			return lastErr
		}
		return timeouterr
	}
	return nil
}

// AssertResultServerMinTLSVersion verifies that the result server created for
// the given scan uses the expected minimum TLS version. It fetches client
// certificates from the scan's Kubernetes secret and uses curl with mTLS to
// connect to the result server endpoint.
func (f *Framework) AssertResultServerMinTLSVersion(scanName, expectedMinTLSVersion string) error {
	ocPath, err := exec.LookPath("oc")
	if err != nil {
		return fmt.Errorf("oc not found: %w", err)
	}

	var lastErr error
	timeouterr := wait.Poll(RetryInterval, Timeout, func() (bool, error) {
		clientCertSecret, err := f.KubeClient.CoreV1().Secrets(f.OperatorNamespace).Get(
			context.TODO(), "result-client-cert-"+scanName, metav1.GetOptions{},
		)
		if err != nil {
			lastErr = fmt.Errorf("failed to get client cert secret: %v", err)
			log.Printf("%v... retrying\n", lastErr)
			return false, nil
		}

		certB64 := base64.StdEncoding.EncodeToString(clientCertSecret.Data["tls.crt"])
		keyB64 := base64.StdEncoding.EncodeToString(clientCertSecret.Data["tls.key"])

		endpoint := fmt.Sprintf("https://%s-rs:8443/", scanName)
		curlCMD := fmt.Sprintf(
			"echo '%s' | base64 -d > /tmp/client.crt && "+
				"echo '%s' | base64 -d > /tmp/client.key && "+
				"curl -vks --cert /tmp/client.crt --key /tmp/client.key %s 2>&1 | grep 'SSL connection'",
			certB64, keyB64, endpoint,
		)

		// #nosec G204
		cmd := exec.Command(ocPath,
			"run", "--rm", "-i", "--restart=Never",
			"--image=registry.fedoraproject.org/fedora-minimal:latest",
			"-n", f.OperatorNamespace, "rs-tls-version-test",
			"--", "bash", "-c", curlCMD,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			lastErr = fmt.Errorf("curl command failed: %v, output: %s", err, string(out))
			log.Printf("%v... retrying\n", lastErr)
			return false, nil
		}

		output := string(out)
		actual := parseTLSVersionFromCurlOutput(output)
		if actual == "" {
			lastErr = fmt.Errorf("could not parse TLS version from result server output: %s", output)
			log.Printf("%v... retrying\n", lastErr)
			return false, nil
		}
		if !tlsVersionAtLeast(actual, expectedMinTLSVersion) {
			lastErr = fmt.Errorf("result server negotiated TLS version %s is below minimum %s", actual, expectedMinTLSVersion)
			log.Printf("%v... retrying\n", lastErr)
			return false, nil
		}
		log.Printf("result server using %s (minimum: %s)\n", actual, expectedMinTLSVersion)
		return true, nil
	})
	if timeouterr != nil {
		if lastErr != nil {
			return lastErr
		}
		return timeouterr
	}
	return nil
}

// AssertMetricsEndpointRejectsTLSVersion verifies that the metrics endpoint
// rejects connections limited to the given TLS version. This is the inverse of
// AssertMetricsEndpointMinTLSVersion: it proves the server's floor is actually
// above the given version by confirming the handshake fails.
func (f *Framework) AssertMetricsEndpointRejectsTLSVersion(rejectedTLSVersion string) error {
	endpoint := fmt.Sprintf("https://metrics.%s.svc:8585/metrics-co", f.OperatorNamespace)
	curlCMD := fmt.Sprintf("curl -vks --tls-max %s %s 2>&1", rejectedTLSVersion, endpoint)

	ocPath, err := exec.LookPath("oc")
	if err != nil {
		return fmt.Errorf("oc not found: %w", err)
	}

	var lastErr error
	timeouterr := wait.Poll(RetryInterval, Timeout, func() (bool, error) {
		// #nosec G204
		cmd := exec.Command(ocPath,
			"run", "--rm", "-i", "--restart=Never",
			"--image=registry.fedoraproject.org/fedora-minimal:latest",
			"-n", f.OperatorNamespace, "tls-reject-test",
			"--", "bash", "-c", curlCMD,
		)
		out, err := cmd.CombinedOutput()
		output := string(out)

		if err == nil && !strings.Contains(output, "SSL") && !strings.Contains(output, "alert") {
			lastErr = fmt.Errorf("expected connection with --tls-max %s to be rejected, but it succeeded: %s", rejectedTLSVersion, output)
			log.Printf("%v... retrying\n", lastErr)
			return false, nil
		}
		log.Printf("metrics endpoint correctly rejected connection capped at %s\n", rejectedTLSVersion)
		return true, nil
	})
	if timeouterr != nil {
		if lastErr != nil {
			return lastErr
		}
		return timeouterr
	}
	return nil
}

// AssertResultServerRejectsTLSVersion verifies that the result server for the
// given scan rejects connections limited to the given TLS version. This proves
// the server's TLS floor is above the capped version by confirming the
// handshake fails.
func (f *Framework) AssertResultServerRejectsTLSVersion(scanName, rejectedTLSVersion string) error {
	ocPath, err := exec.LookPath("oc")
	if err != nil {
		return fmt.Errorf("oc not found: %w", err)
	}

	var lastErr error
	timeouterr := wait.Poll(RetryInterval, Timeout, func() (bool, error) {
		clientCertSecret, err := f.KubeClient.CoreV1().Secrets(f.OperatorNamespace).Get(
			context.TODO(), "result-client-cert-"+scanName, metav1.GetOptions{},
		)
		if err != nil {
			lastErr = fmt.Errorf("failed to get client cert secret: %v", err)
			log.Printf("%v... retrying\n", lastErr)
			return false, nil
		}

		certB64 := base64.StdEncoding.EncodeToString(clientCertSecret.Data["tls.crt"])
		keyB64 := base64.StdEncoding.EncodeToString(clientCertSecret.Data["tls.key"])

		endpoint := fmt.Sprintf("https://%s-rs:8443/", scanName)
		curlCMD := fmt.Sprintf(
			"echo '%s' | base64 -d > /tmp/client.crt && "+
				"echo '%s' | base64 -d > /tmp/client.key && "+
				"curl -vks --tls-max %s --cert /tmp/client.crt --key /tmp/client.key %s 2>&1",
			certB64, keyB64, rejectedTLSVersion, endpoint,
		)

		// #nosec G204
		cmd := exec.Command(ocPath,
			"run", "--rm", "-i", "--restart=Never",
			"--image=registry.fedoraproject.org/fedora-minimal:latest",
			"-n", f.OperatorNamespace, "rs-tls-reject-test",
			"--", "bash", "-c", curlCMD,
		)
		out, err := cmd.CombinedOutput()
		output := string(out)

		if err == nil && !strings.Contains(output, "SSL") && !strings.Contains(output, "alert") {
			lastErr = fmt.Errorf("expected result server connection with --tls-max %s to be rejected, but it succeeded: %s", rejectedTLSVersion, output)
			log.Printf("%v... retrying\n", lastErr)
			return false, nil
		}
		log.Printf("result server correctly rejected connection capped at %s\n", rejectedTLSVersion)
		return true, nil
	})
	if timeouterr != nil {
		if lastErr != nil {
			return lastErr
		}
		return timeouterr
	}
	return nil
}

// WaitForNodesToBeSchedulable waits until all nodes in the cluster are
// schedulable and ready. This is useful after changing the APIServer TLS
// profile, which triggers a kube-apiserver rollout that temporarily cordons
// nodes.
func (f *Framework) WaitForNodesToBeSchedulable() error {
	var lastErr error
	timeouterr := wait.Poll(RetryInterval, 20*time.Minute, func() (bool, error) {
		nodes, err := f.KubeClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			lastErr = fmt.Errorf("failed to list nodes: %v", err)
			log.Printf("%v... retrying\n", lastErr)
			return false, nil
		}
		for _, node := range nodes.Items {
			if node.Spec.Unschedulable {
				lastErr = fmt.Errorf("node %s is unschedulable", node.Name)
				log.Printf("%v... retrying\n", lastErr)
				return false, nil
			}
			ready := false
			for _, cond := range node.Status.Conditions {
				if cond.Type == corev1.NodeReady && cond.Status == corev1.ConditionTrue {
					ready = true
					break
				}
			}
			if !ready {
				lastErr = fmt.Errorf("node %s is not ready", node.Name)
				log.Printf("%v... retrying\n", lastErr)
				return false, nil
			}
		}
		return true, nil
	})
	if timeouterr != nil {
		if lastErr != nil {
			return lastErr
		}
		return timeouterr
	}
	return nil
}

// extractTLSProfileForTest mirrors the operator's logic for determining
// which TLS profile to use based on the APIServer adherence policy.
func extractTLSProfileForTest(apiServer *configv1.APIServer) *configv1.TLSSecurityProfile {
	switch apiServer.Spec.TLSAdherence {
	case configv1.TLSAdherencePolicyStrictAllComponents:
		if apiServer.Spec.TLSSecurityProfile != nil {
			return apiServer.Spec.TLSSecurityProfile
		}
		return &configv1.TLSSecurityProfile{
			Type: configv1.TLSProfileIntermediateType,
		}
	default:
		// When adherence is not strict, the operator uses secure defaults
		// (Intermediate profile from library-go's SecureTLSConfig).
		return &configv1.TLSSecurityProfile{
			Type: configv1.TLSProfileIntermediateType,
		}
	}
}

// GetOperatorPods returns the compliance-operator pods in the operator namespace.
func (f *Framework) GetOperatorPods() ([]corev1.Pod, error) {
	podList, err := f.KubeClient.CoreV1().Pods(f.OperatorNamespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}
	var operatorPods []corev1.Pod
	for _, pod := range podList.Items {
		if strings.Contains(pod.Name, "compliance-operator") &&
			!strings.Contains(pod.Name, "compliance-operator-result") {
			operatorPods = append(operatorPods, pod)
		}
	}
	return operatorPods, nil
}

// WaitForOperatorPodRestart waits until the operator pod has a different UID
// than the one provided, indicating the pod has been restarted.
func (f *Framework) WaitForOperatorPodRestart(originalPodUID types.UID) error {
	return wait.Poll(RetryInterval, Timeout, func() (bool, error) {
		pods, err := f.GetOperatorPods()
		if err != nil {
			log.Printf("Error getting operator pods: %v... retrying\n", err)
			return false, nil
		}
		for _, pod := range pods {
			if pod.UID != originalPodUID && pod.Status.Phase == corev1.PodRunning {
				log.Printf("Operator pod restarted: new UID %s\n", pod.UID)
				return true, nil
			}
		}
		log.Println("Waiting for operator pod to restart...")
		return false, nil
	})
}

// IsOCPVersionAtLeast checks whether the cluster is running at least the
// specified OCP version (e.g. 4, 22 for OCP 4.22). Returns false if the
// ClusterVersion resource cannot be fetched or has no history.
func (f *Framework) IsOCPVersionAtLeast(major, minor int) (bool, error) {
	clusterVersion := &configv1.ClusterVersion{}
	key := types.NamespacedName{Name: "version"}
	if err := f.Client.Get(context.TODO(), key, clusterVersion); err != nil {
		return false, fmt.Errorf("failed to get ClusterVersion: %w", err)
	}
	if len(clusterVersion.Status.History) == 0 {
		return false, fmt.Errorf("ClusterVersion has no history entries")
	}
	version := clusterVersion.Status.History[0].Version
	if !semver.IsValid("v" + version) {
		return false, fmt.Errorf("unexpected version format: %s", version)
	}
	return semver.Compare("v"+version, fmt.Sprintf("v%d.%d.0", major, minor)) >= 0, nil
}
