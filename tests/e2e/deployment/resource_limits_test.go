package deployment_e2e

import (
	"context"
	"fmt"
	"log"
	"testing"

	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	defaultOperatorCPULimit   = "200m"
	defaultOperatorMemLimit   = "500Mi"
	defaultOperatorCPURequest = "10m"
	defaultOperatorMemRequest = "20Mi"

	patchedOperatorCPULimit   = "256m"
	patchedOperatorMemLimit   = "512Mi"
	patchedOperatorCPURequest = "25m"
	patchedOperatorMemRequest = "52Mi"
)

// TestOperatorResourceLimitsConfigurable tests that the compliance operator's
// resource limits and requests can be configured via patching the deployment.
func TestOperatorResourceLimitsConfigurable(t *testing.T) {
	f := framework.Global
	deploymentName := "compliance-operator"

	// Get the compliance-operator deployment
	deployment := &appsv1.Deployment{}
	err := f.Client.Get(context.TODO(), types.NamespacedName{
		Name:      deploymentName,
		Namespace: f.OperatorNamespace,
	}, deployment)
	if err != nil {
		t.Fatalf("failed to get compliance-operator deployment: %s", err)
	}

	// Verify default resource limits
	t.Log("Verifying default resource limits for compliance-operator")
	if len(deployment.Spec.Template.Spec.Containers) == 0 {
		t.Fatal("no containers found in deployment")
	}

	container := deployment.Spec.Template.Spec.Containers[0]
	if container.Name != "compliance-operator" {
		t.Fatalf("expected container name 'compliance-operator', got %s", container.Name)
	}

	// Check default limits
	defaultCPULimit := container.Resources.Limits.Cpu().String()
	defaultMemLimit := container.Resources.Limits.Memory().String()
	defaultCPURequest := container.Resources.Requests.Cpu().String()
	defaultMemRequest := container.Resources.Requests.Memory().String()

	if defaultCPULimit != defaultOperatorCPULimit {
		t.Errorf("expected default CPU limit %s, got %s", defaultOperatorCPULimit, defaultCPULimit)
	}
	if defaultMemLimit != defaultOperatorMemLimit {
		t.Errorf("expected default memory limit %s, got %s", defaultOperatorMemLimit, defaultMemLimit)
	}
	if defaultCPURequest != defaultOperatorCPURequest {
		t.Errorf("expected default CPU request %s, got %s", defaultOperatorCPURequest, defaultCPURequest)
	}
	if defaultMemRequest != defaultOperatorMemRequest {
		t.Errorf("expected default memory request %s, got %s", defaultOperatorMemRequest, defaultMemRequest)
	}

	// Patch the deployment with new resource limits
	t.Log("Patching deployment with new resource limits")

	// Create a patch to update resource requirements
	patchData := []byte(fmt.Sprintf(`{
		"spec": {
			"template": {
				"spec": {
					"containers": [{
						"name": "compliance-operator",
						"resources": {
							"limits": {
								"cpu": "%s",
								"memory": "%s"
							},
							"requests": {
								"cpu": "%s",
								"memory": "%s"
							}
						}
					}]
				}
			}
		}
	}`, patchedOperatorCPULimit, patchedOperatorMemLimit, patchedOperatorCPURequest, patchedOperatorMemRequest))

	// Get the current pod UID before patching to detect when a new pod is created
	podList := &corev1.PodList{}
	err = f.Client.List(context.TODO(), podList,
		client.InNamespace(f.OperatorNamespace),
		client.MatchingLabels(map[string]string{"name": "compliance-operator"}))
	if err != nil {
		t.Fatalf("failed to list operator pods before patch: %s", err)
	}
	if len(podList.Items) == 0 {
		t.Fatal("no compliance-operator pods found before patch")
	}

	var oldPodUID types.UID
	foundRunning := false
	for i := range podList.Items {
		if podList.Items[i].Status.Phase == corev1.PodRunning {
			oldPodUID = podList.Items[i].UID
			foundRunning = true
			break
		}
	}
	if !foundRunning {
		t.Fatal("no Running compliance-operator pod found before patch")
	}

	// Patch the Deployment directly. OLM does not continuously reconcile
	// Deployment specs back to the CSV; it only does so on CSV updates or
	// operator upgrades, so the patch persists for the duration of this test.
	err = f.Client.Patch(context.TODO(), deployment, client.RawPatch(types.StrategicMergePatchType, patchData))
	if err != nil {
		t.Fatalf("failed to patch deployment: %s", err)
	}

	// Defer cleanup: restore original resource limits using the values captured
	// from the deployment before patching
	defer func() {
		t.Log("Restoring original resource limits")
		restorePatch := []byte(fmt.Sprintf(`{
			"spec": {
				"template": {
					"spec": {
						"containers": [{
							"name": "compliance-operator",
							"resources": {
								"limits": {
									"cpu": "%s",
									"memory": "%s"
								},
								"requests": {
									"cpu": "%s",
									"memory": "%s"
								}
							}
						}]
					}
				}
			}
		}`, defaultCPULimit, defaultMemLimit, defaultCPURequest, defaultMemRequest))

		// Get fresh deployment object for restore
		freshDeployment := &appsv1.Deployment{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{
			Name:      deploymentName,
			Namespace: f.OperatorNamespace,
		}, freshDeployment); err != nil {
			t.Logf("failed to get deployment for restore: %s", err)
			return
		}

		if err := f.Client.Patch(context.TODO(), freshDeployment, client.RawPatch(types.StrategicMergePatchType, restorePatch)); err != nil {
			t.Logf("failed to restore original resource limits: %s", err)
		}

		// Wait for deployment to be ready with original limits
		if err := f.WaitForDeployment(deploymentName, 1, framework.RetryInterval, framework.Timeout); err != nil {
			t.Logf("deployment did not become ready after restore: %s", err)
		}
	}()

	// Wait for a new pod to be created with the updated resource limits
	// We poll until we find a pod with a different UID (new pod) that has the expected resources
	t.Log("Waiting for new pod with updated resource limits")
	var newPod *corev1.Pod
	err = wait.Poll(framework.RetryInterval, framework.Timeout, func() (bool, error) {
		podList := &corev1.PodList{}
		listErr := f.Client.List(context.TODO(), podList,
			client.InNamespace(f.OperatorNamespace),
			client.MatchingLabels(map[string]string{"name": "compliance-operator"}))
		if listErr != nil {
			log.Printf("failed to list operator pods: %s, retrying...", listErr)
			return false, nil
		}

		if len(podList.Items) == 0 {
			log.Printf("no compliance-operator pods found yet, waiting...")
			return false, nil
		}

		for i := range podList.Items {
			pod := &podList.Items[i]
			if pod.UID == oldPodUID {
				continue
			}
			if pod.Status.Phase != corev1.PodRunning {
				log.Printf("new pod exists but not running yet (phase: %s), waiting...", pod.Status.Phase)
				return false, nil
			}
			newPod = pod
			log.Printf("new pod found with UID: %s, phase: %s", pod.UID, pod.Status.Phase)
			return true, nil
		}

		log.Printf("no new pod found yet (old UID: %s), waiting...", oldPodUID)
		return false, nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for new pod with updated resources: %s", err)
	}

	// Verify the new pod has the updated resource limits
	t.Log("Verifying new resource limits on operator pod")
	if len(newPod.Spec.Containers) == 0 {
		t.Fatal("no containers found in new pod")
	}

	podContainer := newPod.Spec.Containers[0]
	newCPULimit := podContainer.Resources.Limits.Cpu().String()
	newMemLimit := podContainer.Resources.Limits.Memory().String()
	newCPURequest := podContainer.Resources.Requests.Cpu().String()
	newMemRequest := podContainer.Resources.Requests.Memory().String()

	if newCPULimit != patchedOperatorCPULimit {
		t.Errorf("expected new CPU limit %s, got %s", patchedOperatorCPULimit, newCPULimit)
	}
	if newMemLimit != patchedOperatorMemLimit {
		t.Errorf("expected new memory limit %s, got %s", patchedOperatorMemLimit, newMemLimit)
	}
	if newCPURequest != patchedOperatorCPURequest {
		t.Errorf("expected new CPU request %s, got %s", patchedOperatorCPURequest, newCPURequest)
	}
	if newMemRequest != patchedOperatorMemRequest {
		t.Errorf("expected new memory request %s, got %s", patchedOperatorMemRequest, newMemRequest)
	}

	t.Log("Successfully verified operator resource limits are configurable")
}
