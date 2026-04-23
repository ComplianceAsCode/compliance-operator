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
	} else if config.ApiResourceCacheDir != "" {
		// If we have an API resource cache directory, configure file-based fetching
		fileFetcher := fetchers.NewKubernetesFileFetcher(config.ApiResourceCacheDir)
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

// getRuntimeClient builds a controller-runtime client from the standard rest.Config.
func getRuntimeClient(config *rest.Config, scheme *runtime.Scheme) (runtimeclient.Client, error) {
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
	Tailoring           string
	CheckResultDir      string
	Profile             string
	ApiResourceCacheDir string
	ScanType            string
	CCRGeneration       bool
	ScanName            string
	NameSpace           string
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
		conf.ApiResourceCacheDir = apiResourceDir
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
	client, err := getRuntimeClient(restConfig, scheme)
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

// celRuleWrapper provides unified access to both scanner.Rule interface
// and the RulePayload fields needed for ComplianceCheckResult generation.
// Both Rule CRs and CustomRule CRs implement scanner.Rule; this wrapper
// lets us carry the payload metadata alongside the scanner interface.
type celRuleWrapper struct {
	scannerRule scanner.Rule
	payload     *cmpv1alpha1.RulePayload
	labels      map[string]string
	annotations map[string]string
}

// runPlatformScan runs the platform scan based on the profile and inputs.
func (c *CelScanner) runPlatformScan() {
	cmdLog.V(1).Info("Running platform scan")
	// Load and parse the profile
	profile := c.celConfig.Profile
	if profile == "" {
		cmdLog.Error(nil, "Profile not provided", "scanName", c.celConfig.ScanName)
		os.Exit(CelExitCodeError)
	}
	exitCode := CelExitCodeCompliant

	var selectedRules []celRuleWrapper
	var setVars []*cmpv1alpha1.Variable
	var err error

	if c.celConfig.Tailoring != "" {
		// TailoredProfile path: load TP and get selected rules (CustomRules and/or CEL Rules)
		tailoredProfile, tpErr := c.getTailoredProfile(c.celConfig.NameSpace)
		if tpErr != nil {
			cmdLog.Error(tpErr, "Failed to get tailored profile", "name", c.celConfig.Tailoring)
			os.Exit(CelExitCodeError)
		}
		selectedRules, err = c.getSelectedCELRules(tailoredProfile)
		if err != nil {
			cmdLog.Error(err, "Failed to get selected rules for tailored profile", "name", c.celConfig.Tailoring)
			os.Exit(CelExitCodeError)
		}
		// Collect all the variables being set in the tailoredProfile
		setVars, err = c.getVariablesForTailoredProfile(tailoredProfile)
		if err != nil {
			cmdLog.Error(err, "Failed to get set variables for tailored profile", "name", c.celConfig.Tailoring)
			os.Exit(CelExitCodeError)
		}
	} else {
		// Profile path: load Profile CR and get its CEL rules
		selectedRules, err = c.getCELRulesFromProfile(c.celConfig.Profile, c.celConfig.NameSpace)
		if err != nil {
			cmdLog.Error(err, "Failed to get CEL rules from profile", "name", c.celConfig.Profile)
			os.Exit(CelExitCodeError)
		}
		// Load variables referenced by the Profile with their default values.
		// CEL rules reuse Variable CRs created from the XCCDF DataStream.
		setVars, err = c.getVariablesForProfile(c.celConfig.Profile, c.celConfig.NameSpace)
		if err != nil {
			cmdLog.Error(err, "Failed to get variables for profile", "name", c.celConfig.Profile)
			os.Exit(CelExitCodeError)
		}
	}

	// Convert variables to SDK format
	celVariables := make([]scanner.CelVariable, 0, len(setVars))
	for _, v := range setVars {
		celVar := &celVariableAdapter{
			name:      v.Name,
			namespace: v.Namespace,
			value:     v.Value,
		}
		celVariables = append(celVariables, celVar)
	}

	// Build SDK rule list, skipping rules with empty expressions
	sdkRules := make([]scanner.Rule, 0, len(selectedRules))
	for _, rw := range selectedRules {
		if rw.payload.Expression == "" {
			cmdLog.Info("Warning: Skipping rule with empty expression", "rule", rw.scannerRule.Identifier())
			continue
		}
		sdkRules = append(sdkRules, rw.scannerRule)
	}

	// Create scan configuration
	// Note: ApiResourcePath in the SDK expects the cache directory path
	scanConfig := scanner.ScanConfig{
		Rules:              sdkRules,
		Variables:          celVariables,
		ApiResourcePath:    c.celConfig.ApiResourceCacheDir,
		EnableDebugLogging: debugLog,
	}

	// Run the scan using SDK scanner
	ctx := context.Background()
	checkResults, err := c.sdkScanner.Scan(ctx, scanConfig)
	if err != nil {
		cmdLog.Error(err, "Failed to run scan", "scanName", c.celConfig.ScanName)
		os.Exit(CelExitCodeError)
	}

	// Build a lookup map from rule identifier to wrapper for result mapping
	ruleByID := make(map[string]*celRuleWrapper, len(selectedRules))
	for i := range selectedRules {
		ruleByID[selectedRules[i].scannerRule.Identifier()] = &selectedRules[i]
	}

	// Convert SDK results to compliance operator results
	evalResultList := []*cmpv1alpha1.ComplianceCheckResult{}
	// Cache custom metadata per result so we can merge it with the same
	// precedence logic the SCAP/aggregator path uses (operator keys win).
	type customMeta struct {
		labels      map[string]string
		annotations map[string]string
	}
	customMetadataByName := make(map[string]customMeta)
	for _, result := range checkResults {
		rw, found := ruleByID[result.ID]
		if !found {
			cmdLog.Info("Warning: Could not find corresponding rule for check result", "resultID", result.ID, "reason", "unable to link check result to the rule that produced it")
			continue
		}

		// Generate a DNS-friendly name from the scan name and rule ID
		checkResultName := fmt.Sprintf("%s-%s", c.celConfig.ScanName, utils.IDToDNSFriendlyName(rw.payload.ID))

		// Extract custom (non-operator-managed) labels/annotations from the CustomRule.
		// These will be merged into the check result after operator-managed keys are
		// set, using MergeCustomMetadata (operator keys take precedence).
		cl, ca := utils.GetCustomMetadata(rw.labels, rw.annotations)
		customMetadataByName[checkResultName] = customMeta{labels: cl, annotations: ca}

		compResult := &cmpv1alpha1.ComplianceCheckResult{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "compliance.openshift.io/v1alpha1",
				Kind:       "ComplianceCheckResult",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      checkResultName,
				Namespace: c.celConfig.NameSpace,
			},
			ID:           rw.payload.ID,
			Description:  rw.payload.Description,
			Rationale:    rw.payload.Rationale,
			Severity:     cmpv1alpha1.ComplianceCheckResultSeverity(rw.payload.Severity),
			Instructions: rw.payload.Instructions,
			Warnings:     result.Warnings,
		}

		// Map SDK status to compliance operator status
		switch result.Status {
		case scanner.CheckResultPass:
			compResult.Status = cmpv1alpha1.CheckResultPass
		case scanner.CheckResultFail:
			compResult.Status = cmpv1alpha1.CheckResultFail
			exitCode = CelExitCodeNonCompliant
			// Add the FailureReason to warnings when the check fails
			if rw.payload.FailureReason != "" {
				compResult.Warnings = append(compResult.Warnings, rw.payload.FailureReason)
			}
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
	outputFilePath := filepath.Join(c.celConfig.CheckResultDir, "result.json")
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
			os.Exit(CelExitCodeError)
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

			// Merge custom metadata from the CustomRule using the same
			// precedence as the SCAP/aggregator path: operator keys win.
			if cm, ok := customMetadataByName[pr.Name]; ok {
				checkResultLabels, checkResultAnnotations = utils.MergeCustomMetadata(
					checkResultLabels, cm.labels, checkResultAnnotations, cm.annotations)
			}

			crkey := getObjKey(pr.Name, pr.Namespace)
			foundCheckResult := &cmpv1alpha1.ComplianceCheckResult{}
			foundCheckResult.TypeMeta = pr.TypeMeta
			cmdLog.Info("Getting ComplianceCheckResult", "ComplianceCheckResult.Name", crkey.Name,
				"ComplianceCheckResult.Namespace", crkey.Namespace)
			checkResultExists := utils.GetObjectIfFound(context.TODO(), c.client, crkey, foundCheckResult)
			if checkResultExists {
				foundCheckResult.ObjectMeta.DeepCopyInto(&pr.ObjectMeta)
			} else if !scan.Spec.ShowNotApplicable && pr.Status == cmpv1alpha1.CheckResultNotApplicable {
				continue
			}
			// check is owned by the scan
			if err := createOrUpdateResult(c.client, scan, checkResultLabels, checkResultAnnotations, checkResultExists, pr); err != nil {
				cmdLog.Error(err, "Cannot create or update checkResult", "ComplianceCheckResult.Name", pr.Name)
				os.Exit(CelExitCodeError)
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
				os.Exit(CelExitCodeError)
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

// getSelectedCELRules fetches CEL rules referenced in the tailored profile.
// It handles both CustomRule (kind:CustomRule) and Rule CRs (kind:Rule with scannerType=CEL).
// When the TP extends a CEL profile, the base profile rules are loaded and
// DisableRules are applied to filter them out before adding EnableRules.
func (c *CelScanner) getSelectedCELRules(tp *cmpv1alpha1.TailoredProfile) ([]celRuleWrapper, error) {
	var selectedRules []celRuleWrapper
	ruleMap := make(map[string]bool)

	if tp.Spec.Extends != "" {
		baseRules, err := c.getCELRulesFromProfile(tp.Spec.Extends, tp.Namespace)
		if err != nil {
			return nil, fmt.Errorf("loading base profile '%s': %w", tp.Spec.Extends, err)
		}

		disabledSet := make(map[string]bool, len(tp.Spec.DisableRules))
		for _, dr := range tp.Spec.DisableRules {
			disabledSet[dr.Name] = true
		}

		for _, rw := range baseRules {
			name := rw.scannerRule.Identifier()
			if disabledSet[name] {
				cmdLog.Info("Disabling rule from base profile", "rule", name)
				continue
			}
			ruleMap[name] = true
			selectedRules = append(selectedRules, rw)
		}
	}

	for _, selection := range tp.Spec.EnableRules {
		if ruleMap[selection.Name] {
			continue
		}
		ruleMap[selection.Name] = true

		if selection.Kind == cmpv1alpha1.CustomRuleKind {
			rule := &cmpv1alpha1.CustomRule{}
			ruleKey := v1api.NamespacedName{Name: selection.Name, Namespace: tp.Namespace}
			err := c.client.Get(context.TODO(), ruleKey, rule)
			if err != nil {
				if errors.IsNotFound(err) {
					return nil, fmt.Errorf("CustomRule '%s' not found in namespace '%s'", selection.Name, tp.Namespace)
				}
				return nil, fmt.Errorf("fetching CustomRule '%s': %w", selection.Name, err)
			}
			if err := c.validateCELRulePayload(rule.Name, &rule.Spec.RulePayload); err != nil {
				return nil, fmt.Errorf("invalid CustomRule '%s': %w", rule.Name, err)
			}
			selectedRules = append(selectedRules, celRuleWrapper{
				scannerRule: rule,
				payload:     &rule.Spec.RulePayload,
				labels:      rule.GetLabels(),
				annotations: rule.GetAnnotations(),
			})
		} else {
			rule := &cmpv1alpha1.Rule{}
			ruleKey := v1api.NamespacedName{Name: selection.Name, Namespace: tp.Namespace}
			err := c.client.Get(context.TODO(), ruleKey, rule)
			if err != nil {
				if errors.IsNotFound(err) {
					return nil, fmt.Errorf("Rule '%s' not found in namespace '%s'", selection.Name, tp.Namespace)
				}
				return nil, fmt.Errorf("fetching Rule '%s': %w", selection.Name, err)
			}
			if rule.ScannerType != cmpv1alpha1.ScannerTypeCEL {
				return nil, fmt.Errorf("Rule '%s' has scannerType '%s', expected CEL", rule.Name, rule.ScannerType)
			}
			if err := c.validateCELRulePayload(rule.Name, &rule.RulePayload); err != nil {
				return nil, fmt.Errorf("invalid Rule '%s': %w", rule.Name, err)
			}
			selectedRules = append(selectedRules, celRuleWrapper{
				scannerRule: rule,
				payload:     &rule.RulePayload,
				labels:      rule.GetLabels(),
				annotations: rule.GetAnnotations(),
			})
		}
	}

	if len(selectedRules) == 0 {
		cmdLog.Info("Warning: No rules selected from tailored profile", "profile", tp.Name)
	}

	return selectedRules, nil
}

// getCELRulesFromProfile loads a Profile CR and fetches all its CEL-typed Rule CRs.
func (c *CelScanner) getCELRulesFromProfile(profileName, namespace string) ([]celRuleWrapper, error) {
	profile := &cmpv1alpha1.Profile{}
	profileKey := v1api.NamespacedName{Name: profileName, Namespace: namespace}
	if err := c.client.Get(context.TODO(), profileKey, profile); err != nil {
		return nil, fmt.Errorf("fetching Profile '%s': %w", profileName, err)
	}

	var selectedRules []celRuleWrapper
	for _, profileRule := range profile.Rules {
		ruleName := string(profileRule)
		rule := &cmpv1alpha1.Rule{}
		ruleKey := v1api.NamespacedName{Name: ruleName, Namespace: namespace}
		if err := c.client.Get(context.TODO(), ruleKey, rule); err != nil {
			if errors.IsNotFound(err) {
				return nil, fmt.Errorf("Rule '%s' referenced by Profile '%s' not found", ruleName, profileName)
			}
			return nil, fmt.Errorf("fetching Rule '%s': %w", ruleName, err)
		}
		if rule.ScannerType != cmpv1alpha1.ScannerTypeCEL {
			cmdLog.V(1).Info("Skipping non-CEL rule in CEL profile", "rule", ruleName, "scannerType", rule.ScannerType)
			continue
		}
		if err := c.validateCELRulePayload(rule.Name, &rule.RulePayload); err != nil {
			return nil, fmt.Errorf("invalid Rule '%s': %w", rule.Name, err)
		}
		selectedRules = append(selectedRules, celRuleWrapper{
			scannerRule: rule,
			payload:     &rule.RulePayload,
			labels:      rule.GetLabels(),
			annotations: rule.GetAnnotations(),
		})
	}

	if len(selectedRules) == 0 {
		cmdLog.Info("Warning: No CEL rules found in profile", "profile", profileName)
	}

	return selectedRules, nil
}

// validateCELRulePayload validates that a RulePayload has the required CEL fields.
func (c *CelScanner) validateCELRulePayload(name string, payload *cmpv1alpha1.RulePayload) error {
	if payload.Expression == "" {
		return fmt.Errorf("CEL expression is empty")
	}

	if len(payload.Inputs) == 0 {
		return fmt.Errorf("rule has no inputs defined")
	}

	for i, input := range payload.Inputs {
		if input.Name == "" {
			return fmt.Errorf("input %d has empty resource name", i)
		}

		if err := input.KubernetesInputSpec.Validate(); err != nil {
			return fmt.Errorf("input %d validation failed: %w", i, err)
		}
	}

	if payload.FailureReason == "" {
		cmdLog.V(1).Info("Warning: Rule has no error message defined", "rule", name)
	}

	return nil
}

// getVariablesForProfile loads all Variable CRs referenced in the Profile's Values
// list with their default values. CEL rules reuse Variable CRs from the XCCDF DataStream.
func (c *CelScanner) getVariablesForProfile(profileName, namespace string) ([]*cmpv1alpha1.Variable, error) {
	profile := &cmpv1alpha1.Profile{}
	profileKey := v1api.NamespacedName{Name: profileName, Namespace: namespace}
	if err := c.client.Get(context.TODO(), profileKey, profile); err != nil {
		return nil, fmt.Errorf("fetching Profile '%s': %w", profileName, err)
	}

	var vars []*cmpv1alpha1.Variable
	for _, profileValue := range profile.Values {
		variable := &cmpv1alpha1.Variable{}
		varKey := v1api.NamespacedName{Name: string(profileValue), Namespace: namespace}
		err := c.client.Get(context.TODO(), varKey, variable)
		if err != nil {
			if errors.IsNotFound(err) {
				cmdLog.V(1).Info("Variable referenced by profile not found, skipping", "variable", string(profileValue), "profile", profileName)
				continue
			}
			return nil, fmt.Errorf("fetching variable '%s': %w", string(profileValue), err)
		}
		vars = append(vars, variable)
	}

	return vars, nil
}

func (c *CelScanner) getVariablesForTailoredProfile(tp *cmpv1alpha1.TailoredProfile) ([]*cmpv1alpha1.Variable, error) {
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
			return nil, fmt.Errorf("fetching variable '%s' in namespace '%s': %w", sVar.Name, tp.Namespace, err)
		}
		variable.Value = sVar.Value
		setVars = append(setVars, variable)
	}
	return setVars, nil
}

// saveScanResult saves the scan results to a JSON file with proper indentation
func saveScanResult(filePath string, resultsList []*cmpv1alpha1.ComplianceCheckResult) {
	file, err := os.Create(filePath)
	if err != nil {
		panic(fmt.Sprintf("Failed to create result file %s: %v", filePath, err))
	}
	defer file.Close()
	// Serialize the results list to JSON
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(resultsList)
	if err != nil {
		panic(fmt.Sprintf("Failed to encode results list to JSON: %v", err))
	}
}
