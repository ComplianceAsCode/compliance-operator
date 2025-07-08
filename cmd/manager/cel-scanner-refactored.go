/*
Copyright © 2024 Red Hat Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package manager

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/celscanner"
	"github.com/cenkalti/backoff/v4"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	v1api "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var RefactoredCelScannerCmd = &cobra.Command{
	Use:   "cel-scanner-refactored",
	Short: "Refactored CEL based scanner tool using the reusable module",
	Long:  "CEL based scanner tool for Kubernetes resources using the reusable celscanner module",
	Run:   runRefactoredCelScanner,
}

func init() {
	defineCelScannerFlags(RefactoredCelScannerCmd)
}

type refactoredCelScanner struct {
	scanner   *celscanner.Scanner
	client    runtimeclient.Client
	clientset *kubernetes.Clientset
	config    celConfig
}

func runRefactoredCelScanner(cmd *cobra.Command, args []string) {
	celConf := parseCelScannerConfig(cmd)
	scheme := getScheme()
	restConfig := getConfig()
	logf.SetLogger(zap.New())

	kubeClientSet, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		FATAL("Error building kubeClientSet: %v", err)
	}
	client, err := getCelScannerClient(restConfig, scheme)
	if err != nil {
		FATAL("Error building client: %v", err)
	}

	// Create the refactored scanner
	scanner := newRefactoredCelScanner(client, kubeClientSet, *celConf)

	if celConf.ScanType == "Platform" {
		scanner.runPlatformScan()
	} else {
		FATAL("Unsupported scan type: %s", celConf.ScanType)
	}
}

func newRefactoredCelScanner(client runtimeclient.Client, clientSet *kubernetes.Clientset, config celConfig) *refactoredCelScanner {
	// Create resource fetcher
	resourceFetcher := celscanner.NewComplianceOperatorResourceFetcher(client, clientSet)

	// Create logger adapter
	logger := &complianceOperatorLogger{}

	// Create the scanner with our implementations
	scanner := celscanner.NewScanner(resourceFetcher, logger)

	return &refactoredCelScanner{
		scanner:   scanner,
		client:    client,
		clientset: clientSet,
		config:    config,
	}
}

func (r *refactoredCelScanner) runPlatformScan() {
	DBG("Running platform scan using refactored scanner")

	// Load and parse the profile
	profile := r.config.Profile
	if profile == "" {
		FATAL("Profile not provided")
	}

	exitCode := 0

	// Get tailored profile and selected rules
	var selectedRules []*v1alpha1.CustomRule
	var setVars []*v1alpha1.Variable

	if r.config.Tailoring != "" {
		tailoredProfile, err := r.getTailoredProfile(r.config.NameSpace)
		if err != nil {
			FATAL("Failed to get tailored profile: %v", err)
		}

		selectedRules, err = r.getSelectedCustomRules(tailoredProfile)
		if err != nil {
			FATAL("Failed to get selected rules: %v", err)
		}

		setVars, err = r.getSetVariables(tailoredProfile)
		if err != nil {
			FATAL("Failed to get set variables: %v", err)
		}
	} else {
		FATAL("No tailored profile provided")
	}

	// Adapt types to scanner interfaces
	adaptedRules := celscanner.AdaptCustomRules(selectedRules)
	adaptedVariables := celscanner.AdaptVariables(setVars)

	// Configure the scan
	scanConfig := celscanner.ScanConfig{
		Rules:           adaptedRules,
		Variables:       adaptedVariables,
		ApiResourcePath: r.config.ApiResourcePath,
	}

	// Execute the scan
	ctx := context.Background()
	results, err := r.scanner.Scan(ctx, scanConfig)
	if err != nil {
		FATAL("Failed to execute scan: %v", err)
	}

	// Determine exit code based on results
	for _, result := range results {
		if result.Status == celscanner.CheckResultFail {
			exitCode = 2
		} else if result.Status == celscanner.CheckResultError {
			exitCode = -1
		}
	}

	// Save the scan result
	outputFilePath := filepath.Join(r.config.CheckResultDir, "result.xml")
	if err := celscanner.SaveResults(outputFilePath, results); err != nil {
		FATAL("Failed to save scan results: %v", err)
	}

	// Generate ComplianceCheckResult objects if needed
	if r.config.CCRGeneration {
		if err := r.generateComplianceCheckResults(results); err != nil {
			FATAL("Failed to generate ComplianceCheckResult objects: %v", err)
		}
	}

	// Save exit code
	r.saveExitCode(exitCode)

	os.Exit(0)
}

func (r *refactoredCelScanner) generateComplianceCheckResults(results []celscanner.CheckResult) error {
	DBG("Generating ComplianceCheckResult objects")

	var scan = &v1alpha1.ComplianceScan{}
	err := r.client.Get(context.TODO(), v1api.NamespacedName{
		Namespace: r.config.NameSpace,
		Name:      r.config.ScanName,
	}, scan)
	if err != nil {
		return fmt.Errorf("cannot retrieve the scan instance: %v", err)
	}

	// Get existing ComplianceCheckResults
	staleComplianceCheckResults := make(map[string]v1alpha1.ComplianceCheckResult)
	complianceCheckResults := v1alpha1.ComplianceCheckResultList{}
	withLabel := map[string]string{
		v1alpha1.ComplianceScanLabel: scan.Name,
	}
	lo := runtimeclient.ListOptions{
		Namespace:     scan.Namespace,
		LabelSelector: labels.SelectorFromSet(withLabel),
	}
	err = r.client.List(context.TODO(), &complianceCheckResults, &lo)
	if err != nil {
		return fmt.Errorf("cannot list ComplianceCheckResults: %v", err)
	}

	for _, result := range complianceCheckResults.Items {
		staleComplianceCheckResults[result.Name] = result
	}

	// Convert our results to ComplianceCheckResult objects
	convertedResults := celscanner.ConvertToComplianceCheckResults(results)

	// Create or update ComplianceCheckResult objects
	for _, pr := range convertedResults {
		if pr == nil {
			cmdLog.Info("nil result, this shouldn't happen")
			continue
		}

		checkResultLabels := r.getCheckResultLabels(pr, scan)
		checkResultAnnotations := r.getCheckResultAnnotations(pr)

		crkey := getObjKey(pr.Name, pr.Namespace)
		foundCheckResult := &v1alpha1.ComplianceCheckResult{}
		foundCheckResult.TypeMeta = pr.TypeMeta

		cmdLog.Info("Getting ComplianceCheckResult", "ComplianceCheckResult.Name", crkey.Name,
			"ComplianceCheckResult.Namespace", crkey.Namespace)

		checkResultExists := r.getObjectIfFound(crkey, foundCheckResult)
		if checkResultExists {
			foundCheckResult.ObjectMeta.DeepCopyInto(&pr.ObjectMeta)
		} else if !scan.Spec.ShowNotApplicable && pr.Status == v1alpha1.CheckResultNotApplicable {
			continue
		}

		if err := r.createOrUpdateResult(scan, checkResultLabels, checkResultAnnotations, checkResultExists, pr); err != nil {
			cmdLog.Error(err, "Cannot create or update checkResult", "ComplianceCheckResult.Name", pr.Name)
		}

		// Remove from stale results
		_, ok := staleComplianceCheckResults[foundCheckResult.Name]
		if ok {
			delete(staleComplianceCheckResults, foundCheckResult.Name)
		}
	}

	// Delete stale results
	for _, result := range staleComplianceCheckResults {
		err := r.client.Delete(context.TODO(), &result)
		if err != nil {
			LOG("Unable to delete stale ComplianceCheckResult %s: %v", result.Name, err)
		}
	}

	return nil
}

func (r *refactoredCelScanner) saveExitCode(exitCode int) {
	exitCodeFilePath := filepath.Join(r.config.CheckResultDir, "exit_code")
	err := os.WriteFile(exitCodeFilePath, []byte(fmt.Sprintf("%d", exitCode)), 0644)
	if err != nil {
		FATAL("Failed to write exit code to file: %v", err)
	}
}

func (r *refactoredCelScanner) getTailoredProfile(namespace string) (*v1alpha1.TailoredProfile, error) {
	tailoredProfile := &v1alpha1.TailoredProfile{}
	tpKey := v1api.NamespacedName{Name: r.config.Profile, Namespace: namespace}
	err := r.client.Get(context.TODO(), tpKey, tailoredProfile)
	if err != nil {
		return nil, err
	}
	return tailoredProfile, nil
}

func (r *refactoredCelScanner) getSelectedCustomRules(tp *v1alpha1.TailoredProfile) ([]*v1alpha1.CustomRule, error) {
	var selectedRules []*v1alpha1.CustomRule

	for _, selection := range append(tp.Spec.EnableRules, append(tp.Spec.DisableRules, tp.Spec.ManualRules...)...) {
		for _, rule := range selectedRules {
			if rule.Name == selection.Name {
				return nil, fmt.Errorf("Rule '%s' appears twice in selections", selection.Name)
			}
		}
		rule := &v1alpha1.CustomRule{}
		ruleKey := v1api.NamespacedName{Name: selection.Name, Namespace: tp.Namespace}
		err := r.client.Get(context.TODO(), ruleKey, rule)
		if err != nil {
			return nil, fmt.Errorf("Fetching rule: %w", err)
		}
		selectedRules = append(selectedRules, rule)
	}
	return selectedRules, nil
}

func (r *refactoredCelScanner) getSetVariables(tp *v1alpha1.TailoredProfile) ([]*v1alpha1.Variable, error) {
	var setVars []*v1alpha1.Variable
	for _, sVar := range tp.Spec.SetValues {
		for _, iVar := range setVars {
			if iVar.Name == sVar.Name {
				return nil, fmt.Errorf("Variables '%s' appears twice in selections", sVar.Name)
			}
		}
		variable := &v1alpha1.Variable{}
		varKey := v1api.NamespacedName{Name: sVar.Name, Namespace: tp.Namespace}
		err := r.client.Get(context.TODO(), varKey, variable)
		if err != nil {
			return nil, fmt.Errorf("Fetching variable: %w", err)
		}
		variable.Value = sVar.Value
		setVars = append(setVars, variable)
	}
	return setVars, nil
}

func (r *refactoredCelScanner) getObjectIfFound(key v1api.NamespacedName, obj runtimeclient.Object) bool {
	var found bool
	err := backoff.Retry(func() error {
		err := r.client.Get(context.TODO(), key, obj)
		if errors.IsNotFound(err) {
			return nil
		} else if err != nil {
			cmdLog.Error(err, "Retrying with a backoff because of an error while getting object")
			return err
		}
		found = true
		return nil
	}, backoff.WithMaxRetries(backoff.NewExponentialBackOff(), maxRetries))

	if err != nil {
		cmdLog.Error(err, "Couldn't get object", "Name", key.Name, "Namespace", key.Namespace)
	}
	return found
}

func (r *refactoredCelScanner) createOrUpdateResult(owner metav1.Object, labels map[string]string, annotations map[string]string, exists bool, res *v1alpha1.ComplianceCheckResult) error {
	kind := res.GetObjectKind()

	if err := controllerutil.SetControllerReference(owner, res, r.client.Scheme()); err != nil {
		cmdLog.Error(err, "Failed to set ownership", "kind", kind.GroupVersionKind().Kind)
		return err
	}

	res.SetLabels(labels)
	name := res.GetName()

	err := backoff.Retry(func() error {
		var err error
		if !exists {
			cmdLog.Info("Creating object", "kind", kind, "name", name)
			annotations = setTimestampAnnotations(owner, annotations)
			if annotations != nil {
				res.SetAnnotations(annotations)
			}
			err = r.client.Create(context.TODO(), res)
		} else {
			cmdLog.Info("Updating object", "kind", kind, "name", name)
			annotations = setTimestampAnnotations(owner, annotations)
			if annotations != nil {
				res.SetAnnotations(annotations)
			}
			err = r.client.Update(context.TODO(), res)
		}
		if err != nil && !errors.IsAlreadyExists(err) {
			cmdLog.Error(err, "Retrying with a backoff because of an error while creating or updating object")
			return err
		}
		return nil
	}, backoff.WithMaxRetries(backoff.NewExponentialBackOff(), maxRetries))

	if err != nil {
		cmdLog.Error(err, "Failed to create an object", "kind", kind.GroupVersionKind().Kind)
		return err
	}
	return nil
}

func (r *refactoredCelScanner) getCheckResultLabels(result *v1alpha1.ComplianceCheckResult, scan *v1alpha1.ComplianceScan) map[string]string {
	labels := make(map[string]string)

	// Add scan label
	labels[v1alpha1.ComplianceScanLabel] = scan.Name

	// Add status label
	labels[v1alpha1.ComplianceCheckResultStatusLabel] = string(result.Status)

	// Add severity label
	labels[v1alpha1.ComplianceCheckResultSeverityLabel] = string(result.Severity)

	// Copy existing labels
	if result.Labels != nil {
		for k, v := range result.Labels {
			labels[k] = v
		}
	}

	return labels
}

func (r *refactoredCelScanner) getCheckResultAnnotations(result *v1alpha1.ComplianceCheckResult) map[string]string {
	annotations := make(map[string]string)

	// Add rule annotation
	annotations[v1alpha1.ComplianceCheckResultRuleAnnotation] = result.Name

	// Copy existing annotations
	if result.Annotations != nil {
		for k, v := range result.Annotations {
			annotations[k] = v
		}
	}

	return annotations
}

// complianceOperatorLogger implements the celscanner.Logger interface using the existing logging infrastructure
type complianceOperatorLogger struct{}

func (l *complianceOperatorLogger) Debug(msg string, args ...interface{}) {
	DBG(msg, args...)
}

func (l *complianceOperatorLogger) Info(msg string, args ...interface{}) {
	LOG(msg, args...)
}

func (l *complianceOperatorLogger) Warn(msg string, args ...interface{}) {
	LOG("WARN: "+msg, args...)
}

func (l *complianceOperatorLogger) Error(msg string, args ...interface{}) {
	LOG("ERROR: "+msg, args...)
}
