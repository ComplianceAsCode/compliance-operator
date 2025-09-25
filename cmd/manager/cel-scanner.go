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
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	cmpv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
	"github.com/ComplianceAsCode/compliance-sdk/pkg/fetchers"
	"github.com/ComplianceAsCode/compliance-sdk/pkg/scanner"
	backoff "github.com/cenkalti/backoff/v4"
	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	v1api "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// Exit codes for CEL scanner - matching OpenSCAP conventions
const (
	// CelExitCodeCompliant indicates all checks passed (matches OpenSCAP exit code 0)
	CelExitCodeCompliant = 0
	// CelExitCodeError indicates an error occurred during scanning
	CelExitCodeError = 1
	// CelExitCodeNonCompliant indicates at least one check failed (matches OpenSCAP exit code 2)
	CelExitCodeNonCompliant = 2
)

type CelScanner struct {
	client     runtimeclient.Client
	clientset  *kubernetes.Clientset
	scheme     *runtime.Scheme
	celConfig  celConfig
	sdkScanner *scanner.Scanner
}

// ComplianceLogger adapts controller-runtime logging for SDK
type ComplianceLogger struct {
	debug bool
	log   logr.Logger
}

func (l ComplianceLogger) Debug(msg string, args ...interface{}) {
	if l.debug {
		l.log.V(1).Info(fmt.Sprintf(msg, args...))
	}
}

func (l ComplianceLogger) Info(msg string, args ...interface{}) {
	l.log.Info(fmt.Sprintf(msg, args...))
}

func (l ComplianceLogger) Warn(msg string, args ...interface{}) {
	l.log.Info(fmt.Sprintf("Warning: "+msg, args...))
}

func (l ComplianceLogger) Error(msg string, args ...interface{}) {
	l.log.Error(nil, fmt.Sprintf(msg, args...))
}

func NewCelScanner(scheme *runtime.Scheme, client runtimeclient.Client, clientSet *kubernetes.Clientset, config celConfig) CelScanner {
	// Create SDK-compatible logger using controller-runtime's logger
	logger := ComplianceLogger{
		debug: debugLog,
		log:   cmdLog.WithName("cel-scanner"),
	}

	// Create a composite fetcher
	compositeFetcher := fetchers.NewCompositeFetcher()

	// Add Kubernetes fetcher if we have a valid client
	if client != nil && clientSet != nil {
		kubeFetcher := fetchers.NewKubernetesFetcher(client, clientSet)
		compositeFetcher.RegisterCustomFetcher(scanner.InputTypeKubernetes, kubeFetcher)
	} else if config.ApiResourcePath != "" {
		// If we have an API resource path, configure file-based fetching
		fileFetcher := fetchers.NewKubernetesFileFetcher(config.ApiResourcePath)
		compositeFetcher.RegisterCustomFetcher(scanner.InputTypeKubernetes, fileFetcher)
	}

	// Create SDK scanner with our custom fetcher
	sdkScanner := scanner.NewScanner(&ComplianceFetcherAdapter{
		fetcher: compositeFetcher,
		client:  client,
		scheme:  scheme,
	}, logger)

	return CelScanner{
		client:     client,
		clientset:  clientSet,
		scheme:     scheme,
		celConfig:  config,
		sdkScanner: sdkScanner,
	}
}

// ComplianceFetcherAdapter adapts the SDK fetcher to work with compliance-operator resources
type ComplianceFetcherAdapter struct {
	fetcher scanner.InputFetcher
	client  runtimeclient.Client
	scheme  *runtime.Scheme
}

// celVariableAdapter adapts compliance-operator Variable to SDK CelVariable
type celVariableAdapter struct {
	name      string
	namespace string
	value     string
}

func (v *celVariableAdapter) Name() string      { return v.name }
func (v *celVariableAdapter) Namespace() string { return v.namespace }
func (v *celVariableAdapter) Value() string     { return v.value }
func (v *celVariableAdapter) GroupVersionKind() schema.GroupVersionKind {
	// Variables don't have a GVK, return empty
	return schema.GroupVersionKind{}
}

func (a *ComplianceFetcherAdapter) FetchResources(ctx context.Context, rule scanner.Rule, variables []scanner.CelVariable) (map[string]interface{}, []string, error) {
	warnings := []string{}

	// Validate rule inputs before fetching
	if rule == nil {
		err := fmt.Errorf("rule is nil")
		warnings = append(warnings, err.Error())
		return nil, warnings, err
	}

	inputs := rule.Inputs()
	if len(inputs) == 0 {
		cmdLog.V(1).Info("Rule has no inputs", "ruleID", rule.Identifier())
	}

	// Use the composite fetcher to fetch inputs
	resources, err := a.fetcher.FetchInputs(inputs, variables)

	// Log detailed information for debugging
	if debugLog {
		cmdLog.V(1).Info("Fetched resources for rule",
			"ruleID", rule.Identifier(),
			"inputCount", len(inputs),
			"resourceCount", len(resources),
			"error", err)
	}

	if err != nil {
		// Add context to the error message
		warnings = append(warnings, fmt.Sprintf("Error fetching resources for rule %s: %v", rule.Identifier(), err))
	}

	return resources, warnings, err
}

// getCelScannerClient builds a controller-runtime client from the standard rest.Config.
func getCelScannerClient(config *rest.Config, scheme *runtime.Scheme) (runtimeclient.Client, error) {
	client, err := runtimeclient.New(config, runtimeclient.Options{
		Scheme: scheme,
	})
	if err != nil {
		return nil, err
	}
	return client, nil
}

var CelScannerCmd = &cobra.Command{
	Use:   "cel-scanner",
	Short: "CEL based scanner tool",
	Long:  "CEL based scanner tool for Kubernetes resources",
	Run:   runCelScanner,
}

func init() {
	defineCelScannerFlags(CelScannerCmd)
}

type celConfig struct {
	Tailoring       string
	CheckResultDir  string
	Profile         string
	ApiResourcePath string
	ScanType        string
	CCRGeneration   bool
	ScanName        string
	NameSpace       string
}

func defineCelScannerFlags(cmd *cobra.Command) {
	cmd.Flags().String("tailoring", "", "whether the scan is for tailoring or not.")
	cmd.Flags().String("profile", "", "The scan profile.")
	cmd.Flags().Bool("debug", false, "Print debug messages.")
	cmd.Flags().String("api-resource-dir", "", "The directory containing the pre-fetched API resources, this would be optional, we will try to access the API server if not provided.")
	cmd.Flags().String("scan-type", "", "The type of scan to perform, e.g. Platform.")
	cmd.Flags().String("scan-name", "", "The name of the scan.")
	cmd.Flags().String("check-resultdir", "", "The directory to write the scan results to, this is optional.")
	cmd.Flags().String("enable-ccr-generation", "", "The flag to enable ComplianceCheckResult generation.")
	cmd.Flags().String("namespace", "", "The namespace of the scan.")
	cmd.Flags().String("platform", "", "The platform flag used by CPE detection.")
	flags := cmd.Flags()
	// Add flags registered by imported packages (e.g. glog and controller-runtime)
	flags.AddGoFlagSet(flag.CommandLine)
}

func parseCelScannerConfig(cmd *cobra.Command) *celConfig {
	var conf celConfig
	conf.CheckResultDir = getValidStringArg(cmd, "check-resultdir")
	conf.Profile = getValidStringArg(cmd, "profile")
	debugLog, _ = cmd.Flags().GetBool("debug")
	apiResourceDir, _ := cmd.Flags().GetString("api-resource-dir")
	ccrGeneration, _ := cmd.Flags().GetString("enable-ccr-generation")
	conf.ScanType = getValidStringArg(cmd, "scan-type")
	conf.ScanName = getValidStringArg(cmd, "scan-name")
	conf.NameSpace = getValidStringArg(cmd, "namespace")
	isTailoring, _ := cmd.Flags().GetString("tailoring")
	if isTailoring == "true" {
		tailoredProfileName := conf.Profile
		conf.Tailoring = tailoredProfileName
	}
	if apiResourceDir != "" {
		conf.ApiResourcePath = apiResourceDir
	}
	if ccrGeneration == "true" {
		conf.CCRGeneration = true
	}
	return &conf
}

func runCelScanner(cmd *cobra.Command, args []string) {
	celConf := parseCelScannerConfig(cmd)
	scheme := getScheme()
	restConfig := getConfig()
	logf.SetLogger(zap.New())

	kubeClientSet, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		cmdLog.Error(err, "Error building kubeClientSet")
		os.Exit(CelExitCodeError)
	}
	client, err := getCelScannerClient(restConfig, scheme)
	if err != nil {
		cmdLog.Error(err, "Error building client")
		os.Exit(CelExitCodeError)
	}

	scanner := NewCelScanner(scheme, client, kubeClientSet, *celConf)
	if celConf.ScanType == "Platform" {
		scanner.runPlatformScan()
	} else {
		cmdLog.Error(nil, "Unsupported scan type", "scanType", celConf.ScanType)
		os.Exit(CelExitCodeError)
	}
}

// runPlatformScan runs the platform scan based on the profile and inputs.
func (c *CelScanner) runPlatformScan() {
	cmdLog.V(1).Info("Running platform scan")
	// Load and parse the profile
	profile := c.celConfig.Profile
	if profile == "" {
		cmdLog.Error(nil, "Profile not provided")
		os.Exit(CelExitCodeError)
	}
	exitCode := CelExitCodeCompliant
	// Check if a tailored profile is provided, and get selected rules
	var selectedRules []*cmpv1alpha1.CustomRule
	var setVars []*cmpv1alpha1.Variable
	if c.celConfig.Tailoring != "" {
		tailoredProfile, err := c.getTailoredProfile(c.celConfig.NameSpace)
		if err != nil {
			cmdLog.Error(err, "Failed to get tailored profile")
			os.Exit(CelExitCodeError)
		}
		selectedRules, err = c.getSelectedCustomRules(tailoredProfile)
		if err != nil {
			cmdLog.Error(err, "Failed to get selected rules")
			os.Exit(CelExitCodeError)
		}
		// Collect all the variables being set in the tailoredProfile
		setVars, err = c.getSetVariables(tailoredProfile)
		if err != nil {
			cmdLog.Error(err, "Failed to get set variables")
			os.Exit(CelExitCodeError)
		}
	} else {
		cmdLog.Error(nil, "No tailored profile provided")
		os.Exit(CelExitCodeError)
	}

	// Convert variables to SDK format
	celVariables := make([]scanner.CelVariable, 0, len(setVars))
	for _, v := range setVars {
		// Create an inline adapter for Variable to CelVariable
		celVar := &celVariableAdapter{
			name:      v.Name,
			namespace: v.Namespace,
			value:     v.Value,
		}
		celVariables = append(celVariables, celVar)
	}

	// Convert CustomRules to SDK Rules
	// CustomRule now properly implements scanner.Rule and scanner.CelRule interfaces
	sdkRules := make([]scanner.Rule, 0, len(selectedRules))
	for _, customRule := range selectedRules {
		// Validate the rule before adding it
		if customRule == nil {
			cmdLog.Info("Warning: Skipping nil custom rule")
			continue
		}
		if customRule.Spec.CELPayload.Expression == "" {
			cmdLog.Info("Warning: Skipping rule with empty expression", "rule", customRule.Name)
			continue
		}
		sdkRules = append(sdkRules, customRule)
	}

	// Create scan configuration
	scanConfig := scanner.ScanConfig{
		Rules:              sdkRules,
		Variables:          celVariables,
		ApiResourcePath:    c.celConfig.ApiResourcePath,
		EnableDebugLogging: debugLog,
	}

	// Run the scan using SDK scanner
	ctx := context.Background()
	checkResults, err := c.sdkScanner.Scan(ctx, scanConfig)
	if err != nil {
		cmdLog.Error(err, "Failed to run scan")
		os.Exit(CelExitCodeError)
	}

	// Convert SDK results to compliance operator results
	evalResultList := []*cmpv1alpha1.ComplianceCheckResult{}
	for _, result := range checkResults {
		// Find the original rule to get additional metadata
		var originalRule *cmpv1alpha1.CustomRule
		for _, rule := range selectedRules {
			// Use the Identifier() method for consistency with the interface
			if rule.Identifier() == result.ID {
				originalRule = rule
				break
			}
		}

		if originalRule == nil {
			cmdLog.Info("Warning: Could not find original rule for result", "resultID", result.ID)
			continue
		}

		// Convert SDK CheckResult to ComplianceCheckResult
		// Generate a DNS-friendly name from the scan name and rule ID
		checkResultName := fmt.Sprintf("%s-%s", c.celConfig.ScanName, utils.IDToDNSFriendlyName(originalRule.Spec.ID))

		compResult := &cmpv1alpha1.ComplianceCheckResult{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "compliance.openshift.io/v1alpha1",
				Kind:       "ComplianceCheckResult",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      checkResultName,
				Namespace: c.celConfig.NameSpace,
			},
			ID:           originalRule.Spec.ID,
			Description:  originalRule.Spec.Description,
			Rationale:    originalRule.Spec.Rationale,
			Severity:     cmpv1alpha1.ComplianceCheckResultSeverity(originalRule.Spec.Severity),
			Instructions: originalRule.Spec.Instructions,
			Warnings:     result.Warnings,
		}

		// Map SDK status to compliance operator status
		switch result.Status {
		case scanner.CheckResultPass:
			compResult.Status = cmpv1alpha1.CheckResultPass
		case scanner.CheckResultFail:
			compResult.Status = cmpv1alpha1.CheckResultFail
			exitCode = CelExitCodeNonCompliant
		case scanner.CheckResultError:
			compResult.Status = cmpv1alpha1.CheckResultError
			exitCode = CelExitCodeError
		case scanner.CheckResultNotApplicable:
			compResult.Status = cmpv1alpha1.CheckResultNotApplicable
		}

		if result.ErrorMessage != "" {
			compResult.Warnings = append(compResult.Warnings, result.ErrorMessage)
		}

		evalResultList = append(evalResultList, compResult)
	}

	// Save the scan result
	outputFilePath := filepath.Join(c.celConfig.CheckResultDir, "result.xml")
	saveScanResult(outputFilePath, evalResultList)

	// Check if we need to generate ComplianceCheckResult objects
	if c.celConfig.CCRGeneration {
		cmdLog.V(1).Info("Generating ComplianceCheckResult objects")
		var scan = &cmpv1alpha1.ComplianceScan{}
		err := c.client.Get(context.TODO(), v1api.NamespacedName{
			Namespace: c.celConfig.NameSpace,
			Name:      c.celConfig.ScanName,
		}, scan)
		if err != nil {
			cmdLog.Error(err, "Cannot retrieve the scan instance",
				"ComplianceScan.Name", c.celConfig.ScanName,
				"ComplianceScan.Namespace", c.celConfig.NameSpace,
			)
			os.Exit(CelExitCodeError)
		}

		staleComplianceCheckResults := make(map[string]cmpv1alpha1.ComplianceCheckResult)
		complianceCheckResults := cmpv1alpha1.ComplianceCheckResultList{}
		withLabel := map[string]string{
			cmpv1alpha1.ComplianceScanLabel: scan.Name,
		}
		lo := runtimeclient.ListOptions{
			Namespace:     scan.Namespace,
			LabelSelector: labels.SelectorFromSet(withLabel),
		}
		err = c.client.List(context.TODO(), &complianceCheckResults, &lo)
		if err != nil {
			cmdLog.Error(err, "Cannot list ComplianceCheckResults", "ComplianceScan.Name", scan.Name)
		}
		for _, r := range complianceCheckResults.Items {
			staleComplianceCheckResults[r.Name] = r
		}

		for _, pr := range evalResultList {
			if pr == nil {
				cmdLog.Info("nil result, this shouldn't happen")
				continue
			}

			parsedResult := &utils.ParseResult{}
			parsedResult.CheckResult = pr
			checkResultLabels := getCheckResultLabels(parsedResult, pr.Labels, scan)
			checkResultAnnotations := getCheckResultAnnotations(pr, pr.Annotations)

			crkey := getObjKey(pr.Name, pr.Namespace)
			foundCheckResult := &cmpv1alpha1.ComplianceCheckResult{}
			foundCheckResult.TypeMeta = pr.TypeMeta
			cmdLog.Info("Getting ComplianceCheckResult", "ComplianceCheckResult.Name", crkey.Name,
				"ComplianceCheckResult.Namespace", crkey.Namespace)
			checkResultExists := getObjectIfFoundCEL(c.client, crkey, foundCheckResult)
			if checkResultExists {
				foundCheckResult.ObjectMeta.DeepCopyInto(&pr.ObjectMeta)
			} else if !scan.Spec.ShowNotApplicable && pr.Status == cmpv1alpha1.CheckResultNotApplicable {
				continue
			}
			// check is owned by the scan
			if err := createOrUpdateResult(c.client, scan, checkResultLabels, checkResultAnnotations, checkResultExists, pr); err != nil {
				cmdLog.Error(err, "Cannot create or update checkResult", "ComplianceCheckResult.Name", pr.Name)
			}

			// Remove the ComplianceCheckResult from the list of stale results
			_, ok := staleComplianceCheckResults[foundCheckResult.Name]
			if ok {
				delete(staleComplianceCheckResults, foundCheckResult.Name)
			}
		}

		// Delete stale ComplianceCheckResults
		for _, result := range staleComplianceCheckResults {
			err := c.client.Delete(context.TODO(), &result)
			if err != nil {
				cmdLog.Error(err, "Unable to delete stale ComplianceCheckResult", "name", result.Name)
			}
		}
	}

	// Save the exit code to a file (matching OpenSCAP behavior)
	// This exit code represents the compliance status (0=compliant, 2=non-compliant)
	exitCodeFilePath := filepath.Join(c.celConfig.CheckResultDir, "exit_code")
	err = os.WriteFile(exitCodeFilePath, []byte(fmt.Sprintf("%d", exitCode)), 0644)
	if err != nil {
		cmdLog.Error(err, "Failed to write exit code to file")
		os.Exit(CelExitCodeError)
	}

	// Log scan completion
	// Note: We exit with 0 (success) regardless of compliance status to prevent pod restarts
	// The actual compliance status is saved in the exit_code file and results
	cmdLog.Info("CEL scan completed successfully", "complianceExitCode", exitCode)
	os.Exit(0) // Always exit with 0 for successful scan completion
}

// Returns whether or not an object exists, and updates the data in the obj.
func getObjectIfFoundCEL(crClient runtimeclient.Client, key v1api.NamespacedName, obj runtimeclient.Object) bool {
	var found bool
	err := backoff.Retry(func() error {
		err := crClient.Get(context.TODO(), key, obj)
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

func createOrUpdateResult(crClient runtimeclient.Client, owner metav1.Object, labels map[string]string, annotations map[string]string, exists bool, res compResultIface) error {
	kind := res.GetObjectKind()

	if err := controllerutil.SetControllerReference(owner, res, crClient.Scheme()); err != nil {
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
			err = crClient.Create(context.TODO(), res)
		} else {
			cmdLog.Info("Updating object", "kind", kind, "name", name)
			annotations = setTimestampAnnotations(owner, annotations)
			if annotations != nil {
				res.SetAnnotations(annotations)
			}
			err = crClient.Update(context.TODO(), res)
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

func (c *CelScanner) getTailoredProfile(namespace string) (*cmpv1alpha1.TailoredProfile, error) {
	tailoredProfile := &cmpv1alpha1.TailoredProfile{}
	tpKey := v1api.NamespacedName{Name: c.celConfig.Profile, Namespace: namespace}
	err := c.client.Get(context.TODO(), tpKey, tailoredProfile)
	if err != nil {
		return nil, err
	}
	return tailoredProfile, nil
}

func (c *CelScanner) getSelectedCustomRules(tp *cmpv1alpha1.TailoredProfile) ([]*cmpv1alpha1.CustomRule, error) {
	var selectedRules []*cmpv1alpha1.CustomRule
	ruleMap := make(map[string]bool) // Track rules to detect duplicates

	allSelections := append(tp.Spec.EnableRules, append(tp.Spec.DisableRules, tp.Spec.ManualRules...)...)

	for _, selection := range allSelections {
		// Check for duplicate rules
		if ruleMap[selection.Name] {
			return nil, fmt.Errorf("rule '%s' appears twice in selections", selection.Name)
		}
		ruleMap[selection.Name] = true

		rule := &cmpv1alpha1.CustomRule{}
		ruleKey := v1api.NamespacedName{Name: selection.Name, Namespace: tp.Namespace}
		err := c.client.Get(context.TODO(), ruleKey, rule)
		if err != nil {
			if errors.IsNotFound(err) {
				return nil, fmt.Errorf("rule '%s' not found in namespace '%s'", selection.Name, tp.Namespace)
			}
			return nil, fmt.Errorf("fetching rule '%s': %w", selection.Name, err)
		}

		// Validate the rule has required fields
		if err := c.validateCustomRule(rule); err != nil {
			return nil, fmt.Errorf("invalid rule '%s': %w", rule.Name, err)
		}

		selectedRules = append(selectedRules, rule)
	}

	if len(selectedRules) == 0 {
		cmdLog.Info("Warning: No rules selected from tailored profile", "profile", tp.Name)
	}

	return selectedRules, nil
}

// validateCustomRule validates that a CustomRule has all required fields
func (c *CelScanner) validateCustomRule(rule *cmpv1alpha1.CustomRule) error {
	if rule == nil {
		return fmt.Errorf("rule is nil")
	}

	if rule.Name == "" {
		return fmt.Errorf("rule name is empty")
	}

	if rule.Spec.CELPayload.Expression == "" {
		return fmt.Errorf("CEL expression is empty")
	}

	if len(rule.Spec.CELPayload.Inputs) == 0 {
		return fmt.Errorf("rule has no inputs defined")
	}

	// Validate each input
	for i, input := range rule.Spec.CELPayload.Inputs {
		if input.Name == "" {
			return fmt.Errorf("input %d has empty resource name", i)
		}

		// Validate KubernetesInputSpec using its own Validate method
		if err := input.KubernetesInputSpec.Validate(); err != nil {
			return fmt.Errorf("input %d validation failed: %w", i, err)
		}
	}

	if rule.Spec.CELPayload.ErrorMessage == "" {
		cmdLog.V(1).Info("Warning: Rule has no error message defined", "rule", rule.Name)
	}

	return nil
}

func (c *CelScanner) getSetVariables(tp *cmpv1alpha1.TailoredProfile) ([]*cmpv1alpha1.Variable, error) {
	var setVars []*cmpv1alpha1.Variable
	for _, sVar := range tp.Spec.SetValues {
		for _, iVar := range setVars {
			if iVar.Name == sVar.Name {
				return nil, fmt.Errorf("variables '%s' appears twice in selections", sVar.Name)
			}
		}
		variable := &cmpv1alpha1.Variable{}
		varKey := v1api.NamespacedName{Name: sVar.Name, Namespace: tp.Namespace}
		err := c.client.Get(context.TODO(), varKey, variable)
		if err != nil {
			return nil, fmt.Errorf("fetching variable: %w", err)
		}
		variable.Value = sVar.Value
		setVars = append(setVars, variable)
	}
	return setVars, nil
}

func saveScanResult(filePath string, resultsList []*cmpv1alpha1.ComplianceCheckResult) {
	file, err := os.Create(filePath)
	if err != nil {
		panic(fmt.Sprintf("Failed to create result file %s: %v", filePath, err))
	}
	defer file.Close()
	// serialize the results map to JSON
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(resultsList)
	if err != nil {
		panic(fmt.Sprintf("Failed to encode results map to JSON: %v", err))
	}
}
