package framework

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/yaml"
)

// GetServiceAccountToken retrieves a service account token for API authentication
func GetServiceAccountToken(f *Framework, namespace string) (string, error) {
	// Grant cluster-admin to the default service account temporarily
	log.Printf("Granting cluster-admin role to system:serviceaccount:%s:default", namespace)
	// Create ClusterRoleBinding to grant cluster-admin permissions
	clusterRoleBindingName := fmt.Sprintf("rapidast-admin-%s", namespace)
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterRoleBindingName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "cluster-admin",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "default",
				Namespace: namespace,
			},
		},
	}

	_, err := f.KubeClient.RbacV1().ClusterRoleBindings().Create(
		context.TODO(),
		clusterRoleBinding,
		metav1.CreateOptions{},
	)
	if err != nil {
		return "", fmt.Errorf("failed to create ClusterRoleBinding: %w", err)
	}

	log.Printf("Successfully created ClusterRoleBinding %s", clusterRoleBindingName)
	// For newer Kubernetes versions, create a token request
	expirationSeconds := int64(3600)
	treq := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			ExpirationSeconds: &expirationSeconds,
		},
	}

	tresp, err := f.KubeClient.CoreV1().ServiceAccounts(namespace).CreateToken(
		context.TODO(),
		"default",
		treq,
		metav1.CreateOptions{},
	)
	if err != nil {
		return "", fmt.Errorf("failed to create token: %w", err)
	}
	return tresp.Status.Token, nil
}

// RunRapidASTScan executes the RapidAST scan using a Kubernetes Job
func RunRapidASTScan(f *Framework, namespace string) error {
	log.Printf("Starting RapidAST scan in namespace %s", namespace)
	// Get service account token
	token, err := GetServiceAccountToken(f, namespace)
	if err != nil {
		return fmt.Errorf("failed to get service account token: %w", err)
	}

	// Cleanup ClusterRoleBinding after scan completes
	clusterRoleBindingName := fmt.Sprintf("rapidast-admin-%s", namespace)
	defer func() {
		log.Printf("Cleaning up ClusterRoleBinding %s", clusterRoleBindingName)
		err := f.KubeClient.RbacV1().ClusterRoleBindings().Delete(
			context.TODO(),
			clusterRoleBindingName,
			metav1.DeleteOptions{},
		)
		if err != nil {
			log.Printf("Warning: failed to delete ClusterRoleBinding %s: %v", clusterRoleBindingName, err)
		} else {
			log.Printf("Successfully deleted ClusterRoleBinding %s", clusterRoleBindingName)
		}
	}()
	// Read the rapidast config template
	testDataDir := filepath.Join(f.projectRoot, "tests", "data", "rapidast")
	configTemplatePath := filepath.Join(testDataDir, "rapidast-config.yaml")
	policyPath := filepath.Join(testDataDir, "customscan.policy")
	jobPath := filepath.Join(testDataDir, "job-rapidast.yaml")

	configTemplate, err := os.ReadFile(configTemplatePath)
	if err != nil {
		return fmt.Errorf("failed to read config template: %w", err)
	}

	// Replace token placeholder
	config := strings.Replace(string(configTemplate), "Bearer sha256~xxxxxxxx", "Bearer "+token, -1)

	// Create temporary config file
	tmpConfigPath := filepath.Join(os.TempDir(), fmt.Sprintf("rapidast-config-%d.yaml", time.Now().Unix()))
	if err := os.WriteFile(tmpConfigPath, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	defer os.Remove(tmpConfigPath)

	// Create ConfigMap with config and policy
	log.Printf("Creating ConfigMap rapidast-configmap in namespace %s", namespace)
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rapidast-configmap",
			Namespace: namespace,
		},
		Data: map[string]string{},
		BinaryData: map[string][]byte{
			"rapidast-config.yaml": []byte(config),
		},
	}

	// Read policy file
	policyData, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}
	configMap.BinaryData["customscan.policy"] = policyData

	_, err = f.KubeClient.CoreV1().ConfigMaps(namespace).Create(context.TODO(), configMap, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create ConfigMap: %w", err)
	}

	// Read and create Job
	log.Printf("Creating Job rapidast-job in namespace %s", namespace)
	jobData, err := os.ReadFile(jobPath)
	if err != nil {
		return fmt.Errorf("failed to read job template: %w", err)
	}

	// Parse Job YAML
	job := &batchv1.Job{}
	if err := yaml.Unmarshal(jobData, job); err != nil {
		return fmt.Errorf("failed to parse job YAML: %w", err)
	}
	job.Namespace = namespace
	_, err = f.KubeClient.BatchV1().Jobs(namespace).Create(context.TODO(), job, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create Job: %w", err)
	}

	// Wait for job to complete (up to 10 minutes)
	log.Printf("Waiting for RapidAST job to complete...")
	err = wait.PollUntilContextTimeout(context.Background(), 30*time.Second, 10*time.Minute, true, func(ctx context.Context) (bool, error) {
		pods, err := f.KubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
			LabelSelector: "job-name=rapidast-job",
		})
		if err != nil {
			log.Printf("Error listing pods: %v", err)
			return false, nil
		}

		if len(pods.Items) == 0 {
			log.Printf("No pods found for rapidast-job yet")
			return false, nil
		}

		pod := pods.Items[0]
		phase := pod.Status.Phase
		log.Printf("RapidAST job pod status: %s", phase)

		if phase == corev1.PodPending || phase == corev1.PodRunning {
			return false, nil
		}
		if phase == corev1.PodFailed {
			return false, fmt.Errorf("rapidast-job failed")
		}
		return phase == corev1.PodSucceeded, nil
	})

	if err != nil {
		return fmt.Errorf("job did not complete successfully: %w", err)
	}

	// Get pod logs
	pods, err := f.KubeClient.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: "job-name=rapidast-job",
	})
	if err != nil || len(pods.Items) == 0 {
		return fmt.Errorf("failed to get job pods: %w", err)
	}

	podName := pods.Items[0].Name
	req := f.KubeClient.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{})
	logs, err := req.Stream(context.TODO())
	if err != nil {
		return fmt.Errorf("failed to get pod logs: %w", err)
	}
	defer logs.Close()

	// Read logs
	logData := new(strings.Builder)
	buf := make([]byte, 2048)
	for {
		n, err := logs.Read(buf)
		if n > 0 {
			logData.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	podLogs := logData.String()

	// Save results to artifact directory if available
	artifactDir := os.Getenv("ARTIFACT_DIR")
	if artifactDir != "" {
		resultsDir := filepath.Join(artifactDir, "rapiddastresultsISC")
		if err := os.MkdirAll(resultsDir, 0755); err == nil {
			resultFile := filepath.Join(resultsDir, "compliance_v1alpha1_rapidast.result")
			if err := os.WriteFile(resultFile, []byte(podLogs), 0644); err != nil {
				log.Printf("Failed to write result file: %v", err)
			} else {
				log.Printf("Wrote DAST results to %s", resultFile)
			}
		}
	}

	// Parse results for high/medium risks
	riskHigh := 0
	riskMedium := 0
	reHigh := regexp.MustCompile(`"riskdesc": .*High`)
	reMedium := regexp.MustCompile(`"riskdesc": .*Medium`)

	lines := strings.Split(podLogs, "\n")
	for _, line := range lines {
		if reHigh.MatchString(line) {
			riskHigh++
		}
		if reMedium.MatchString(line) {
			riskMedium++
		}
	}
	log.Printf("RapidAST scan results: High=%d, Medium=%d", riskHigh, riskMedium)
	if riskHigh > 0 {
		return fmt.Errorf("High risk security issues found: %d", riskHigh)
	}
	return nil
}
