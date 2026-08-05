package fetchraw

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/kubectl/pkg/cmd/cp"
	"k8s.io/kubectl/pkg/cmd/util"

	"github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/common"
)

const (
	rawResultsMountPath = "raw-results"
	cmdLabelKey         = "fetch-compliance-results"
	objNameLabelKey     = "fetch-compliance-results/obj-name"
)

type ComplianceScanHelper struct {
	kuser      common.KubeClientUser
	gvk        schema.GroupVersionResource
	podgvk     schema.GroupVersionResource
	kind       string
	name       string
	outputPath string
	image      string
	html       bool
	genericclioptions.IOStreams
}

func NewComplianceScanHelper(kuser common.KubeClientUser, name, outputPath, image string, html bool, streams genericclioptions.IOStreams) common.ObjectHelper {
	return &ComplianceScanHelper{
		kuser:      kuser,
		name:       name,
		kind:       "ComplianceScan",
		outputPath: outputPath,
		image:      image,
		html:       html,
		gvk: schema.GroupVersionResource{
			Group:    common.CmpAPIGroup,
			Version:  common.CmpResourceVersion,
			Resource: "compliancescans",
		},
		podgvk: schema.GroupVersionResource{
			Group:    "",
			Version:  "v1",
			Resource: "pods",
		},
		IOStreams: streams,
	}
}

func (h *ComplianceScanHelper) Handle() error {
	// Get target resource
	res, err := h.kuser.DynamicClient().Resource(h.gvk).Namespace(h.kuser.GetNamespace()).Get(context.TODO(), h.name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("Unable to get resource %s/%s of type %s: %s", h.kuser.GetNamespace(), h.name, h.kind, err)
	}

	// Get needed data
	phase, err := h.getScanPhase(res)
	if err != nil {
		return err
	}

	ci, err := h.getCurrentIndex(res)
	if err != nil {
		return err
	}

	if ci == 0 && strings.ToLower(phase) != "done" {
		return fmt.Errorf("No results available yet. Please wait for the scan to be done. Current phase: %s", phase)
	}

	rsRef, err := h.getResultsStorageRef(res)
	if err != nil {
		return err
	}

	claimName, found := rsRef["name"]
	if !found {
		return fmt.Errorf("Malformed raw result storage reference. No name available. Check the %s object's status", h.kind)
	}

	rsnamespace, found := rsRef["namespace"]
	if !found {
		return fmt.Errorf("Malformed raw result storage reference. No namespace available. Check the %s object's status", h.kind)
	}

	rsTolerations, err := h.getRsTolerations(res)
	if err != nil {
		return err
	}

	// Create extractor pod
	extractorPod := getPVCExtractorPod(res.GetName(), rsnamespace, h.image, claimName, rsTolerations)
	extractorPod, err = h.kuser.Clientset().CoreV1().Pods(rsnamespace).Create(context.TODO(), extractorPod, metav1.CreateOptions{})
	if err != nil && !kerrors.IsAlreadyExists(err) {
		return err
	}

	// wait for extractor pod
	err = h.waitForExtractorPod(rsnamespace, res.GetName(), extractorPod.GetName())
	if err != nil {
		return err
	}

	cf := NewFetchRawOptions(h.IOStreams).ConfigFlags
	f := util.NewFactory(cf)
	cmd := cp.NewCmdCp(f, h.IOStreams)

	opts := cp.NewCopyOptions(h.IOStreams)
	opts.Namespace = rsnamespace

	podName := extractorPod.GetName()
	path := fmt.Sprintf("%s/%d", rawResultsMountPath, ci)
	cpargs := []string{
		fmt.Sprintf("%s/%s:%s", rsnamespace, podName, path),
		h.outputPath,
	}
	if err = opts.Complete(f, cmd, cpargs); err != nil {
		return err
	}

	c := restclient.CopyConfig(h.kuser.GetConfig())
	cs, err := kubernetes.NewForConfig(c)
	if err != nil {
		return err
	}
	opts.ClientConfig = c
	opts.Clientset = cs

	// run kubectl cp
	if err = opts.Run(); err != nil {
		return err
	}

	fmt.Fprintf(h.Out, "The raw compliance results are avaliable in the following directory: %s\n", h.outputPath)

	// delete extractor pod
	var zeroGP int64 = 0
	err = h.kuser.Clientset().CoreV1().Pods(rsnamespace).Delete(context.TODO(), extractorPod.GetName(), metav1.DeleteOptions{
		GracePeriodSeconds: &zeroGP,
	})
	if err != nil {
		return err
	}

	if h.html {
		return h.generateHTMLReports()
	}
	return nil
}

func (h *ComplianceScanHelper) getScanPhase(obj *unstructured.Unstructured) (string, error) {
	phase, found, err := unstructured.NestedString(obj.Object, "status", "phase")
	if err != nil {
		return "", fmt.Errorf("Unable to get phase of %s/%s of type %s: %s", obj.GetNamespace(), obj.GetName(), "ComplianceScan", err)
	}
	if !found {
		return "", fmt.Errorf("%s/%s of type %s: has no phase in status", obj.GetNamespace(), h.name, h.kind)
	}
	return phase, nil
}

func (h *ComplianceScanHelper) getCurrentIndex(obj *unstructured.Unstructured) (int64, error) {
	curri, found, err := unstructured.NestedInt64(obj.Object, "status", "currentIndex")
	if err != nil {
		return 0, fmt.Errorf("Unable to get currentIndex of %s/%s of type %s: %s", obj.GetNamespace(), obj.GetName(), h.kind, err)
	}
	if !found {
		return 0, nil
	}
	return curri, nil
}

func (h *ComplianceScanHelper) getResultsStorageRef(obj *unstructured.Unstructured) (map[string]string, error) {
	rs, found, err := unstructured.NestedStringMap(obj.Object, "status", "resultsStorage")
	if err != nil {
		return nil, fmt.Errorf("Unable to get resultsStorage of %s/%s of type %s: %s", obj.GetNamespace(), obj.GetName(), "ComplianceScan", err)
	}
	if !found {
		return nil, fmt.Errorf("%s/%s of type %s: has no resultsStorage in status", obj.GetNamespace(), h.name, h.kind)
	}
	return rs, nil
}

func (h *ComplianceScanHelper) getRsTolerations(obj *unstructured.Unstructured) ([]corev1.Toleration, error) {
	rawTolerations, found, err := unstructured.NestedSlice(obj.Object, "spec", "rawResultStorage", "tolerations")
	if err != nil {
		return nil, fmt.Errorf("Unable to get rawResultStorage.tolerations of %s/%s of type %s: %s", obj.GetNamespace(), obj.GetName(), "ComplianceScan", err)
	}
	if !found {
		return nil, nil
	}

	tolerations := make([]corev1.Toleration, 0, len(rawTolerations))
	for _, rawToleration := range rawTolerations {
		var toleration corev1.Toleration
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(
			rawToleration.(map[string]interface{}),
			&toleration,
		); err != nil {
			return nil, fmt.Errorf("failed to convert toleration: %w", err)
		}
		tolerations = append(tolerations, toleration)
	}

	return tolerations, nil
}

func (h *ComplianceScanHelper) waitForExtractorPod(ns, objName, generatedPodName string) error {
	opts := metav1.GetOptions{}
	var lastErr error
	fmt.Fprintf(h.Out, "Fetching raw compliance results for pod '%s'.", generatedPodName)
	fmt.Fprintf(h.Out, "Fetching raw compliance results for scan '%s'.", h.name)
	timeouterr := wait.PollUntilContextTimeout(context.TODO(), common.RetryInterval, common.Timeout, true, func(ctx context.Context) (bool, error) {
		targetpod, err := h.kuser.Clientset().CoreV1().Pods(ns).Get(ctx, generatedPodName, opts)
		if kerrors.IsNotFound(err) {
			return false, nil
		}
		lastErr = err
		if err != nil {
			return false, nil
		}
		if targetpod.Status.Phase == corev1.PodRunning || targetpod.Status.Phase == corev1.PodSucceeded {
			return true, nil
		}
		fmt.Fprint(h.Out, ".")
		return false, nil
	})
	fmt.Fprint(h.Out, "\n")

	if timeouterr != nil {
		return fmt.Errorf("The extractor pod wasn't ready before the timeout")
	}

	if lastErr != nil {
		return lastErr
	}
	return nil
}

func (h *ComplianceScanHelper) generateHTMLReports() error {
	var wg sync.WaitGroup
	done := make(chan bool)
	errors := make(chan error)
	reportFuncs := []func(){}
	filepath.Walk(h.outputPath, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		if !hasExpectedARFExtension(path) {
			return nil
		}
		reportf := func() {
			reportFile := replaceARFforHTMLExt(path)
			reportcmd := exec.Command("oscap", "xccdf", "generate", "report",
				"--output", reportFile, path)
			out, err := reportcmd.CombinedOutput()
			if err != nil {
				fmt.Fprintf(h.Out, string(out))
				errors <- err
			} else {
				fmt.Fprintf(h.Out, "An HTML report is available at %s\n", reportFile)
			}
			wg.Done()
		}
		reportFuncs = append(reportFuncs, reportf)
		return nil
	})

	wg.Add(len(reportFuncs))
	for _, f := range reportFuncs {
		go f()
	}

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		break
	case err := <-errors:
		close(errors)
		return err
	}
	return nil
}

func getPVCExtractorPodLabels(objName string) map[string]string {
	return map[string]string{
		cmdLabelKey:     "",
		objNameLabelKey: objName,
	}
}

func getPVCExtractorPod(objName, ns, image, claimName string, tolerations []corev1.Toleration) *corev1.Pod {
	bFalse := false
	bTrue := true

	if tolerations == nil || len(tolerations) == 0 {
		tolerations = []corev1.Toleration{
			{
				Effect:   corev1.TaintEffectNoSchedule,
				Key:      "node-role.kubernetes.io/master",
				Operator: corev1.TolerationOpExists,
			},
		}
	}

	return &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "raw-result-extractor-",
			Namespace:    ns,
			Labels:       getPVCExtractorPodLabels(objName),
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{
					Name:    "pv-extract-pod",
					Image:   image,
					Command: []string{"sleep", "300"},
					SecurityContext: &corev1.SecurityContext{
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"ALL"},
						},
						Privileged:               &bFalse,
						RunAsNonRoot:              &bTrue,
						AllowPrivilegeEscalation: &bFalse,
						SeccompProfile: &corev1.SeccompProfile{
							Type: "RuntimeDefault",
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "raw-results-vol",
							ReadOnly:  true,
							MountPath: fmt.Sprintf("/%s", rawResultsMountPath),
						},
					},
				},
			},
			Tolerations: tolerations,
			Volumes: []corev1.Volume{
				{
					Name: "raw-results-vol",
					VolumeSource: corev1.VolumeSource{
						PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
							ClaimName: claimName,
						},
					},
				},
			},
		},
	}
}

func hasExpectedARFExtension(path string) bool {
	return strings.HasSuffix(path, ".xml") || strings.HasSuffix(path, ".xml.bzip2")
}

func replaceARFforHTMLExt(path string) string {
	if strings.HasSuffix(path, ".xml.bzip2") {
		return strings.ReplaceAll(path, ".xml.bzip2", ".html")
	}
	if strings.HasSuffix(path, ".xml") {
		return strings.ReplaceAll(path, ".xml", ".html")
	}
	return path + ".html"
}
