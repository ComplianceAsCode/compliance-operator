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
	"strings"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	cmpv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/spf13/cobra"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	v1api "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

type CelScanner struct {
	client client.Client
	resourceFetcherClients
	celConfig celConfig
}

func NewCelScanner(scheme *runtime.Scheme, client client.Client, clientSet *kubernetes.Clientset, config celConfig) CelScanner {
	return CelScanner{
		resourceFetcherClients: resourceFetcherClients{
			clientset: clientSet,
			client:    client,
			scheme:    scheme,
		},
		celConfig: config,
	}
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
}

func defineCelScannerFlags(cmd *cobra.Command) {
	cmd.Flags().String("tailoring", "", "whether the scan is for tailoring or not.")
	cmd.Flags().String("profile", "", "The scan profile.")
	cmd.Flags().Bool("debug", false, "Print debug messages.")
	cmd.Flags().String("api-resource-dir", "", "The directory containing the pre-fetched API resources, this would be optional, we will try to access the API server if not provided.")
	cmd.Flags().String("scan-type", "", "The type of scan to perform, e.g. Platform.")
	cmd.Flags().String("check-resultdir", "", "The directory to write the scan results to, this is optional.")
	cmd.Flags().String("enable-ccr-generation", "", "The flag to enable ComplianceCheckResult generation.")
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
	conf.ApiResourcePath = getValidStringArg(cmd, "api-resource-dir")
	conf.CCRGeneration, _ = cmd.Flags().GetBool("enable-ccr-generation")
	conf.ScanType = getValidStringArg(cmd, "scan-type")
	isTailoring, _ := cmd.Flags().GetString("tailoring")
	if isTailoring == "true" {
		tailoredProfileName := conf.Profile
		conf.Tailoring = tailoredProfileName
	}
	return &conf
}

func runCelScanner(cmd *cobra.Command, args []string) {
	celConf := parseCelScannerConfig(cmd)
	scheme := getScheme()
	client, err := getCelScannerClient(scheme)
	if err != nil {
		FATAL("Error building client: %v", err)
	}

	restConfig := getConfig()

	kubeClientSet, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		FATAL("Error building kubeClientSet: %v", err)
	}
	scanner := NewCelScanner(scheme, client, kubeClientSet, *celConf)
	if celConf.ScanType == "Platform" {
		scanner.runPlatformScan()
	} else {
		FATAL("Unsupported scan type: %s", celConf.ScanType)
	}
}

// runPlatformScan runs the platform scan based on the profile and inputs.
func (c *CelScanner) runPlatformScan() {
	DBG("Running platform scan")
	// Load and parse the profile
	profile := c.celConfig.Profile
	if profile == "" {
		FATAL("Profile not provided")
	}
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}
	exitCode := 0
	// Check if a tailored profile is provided, and get selected rules
	// TODO(@Vincent056): Right now only CEL CustomRules are supported
	// We will add support for Rule Object when CEL is supported for Rule
	var selectedRules []*cmpv1alpha1.CustomRule
	if c.celConfig.Tailoring != "" {
		tailoredProfile, err := c.getTailoredProfile(namespace)
		if err != nil {
			FATAL("Failed to get tailored profile: %v", err)
		}
		selectedRules, err = c.getSelectedCustomRules(tailoredProfile)
		if err != nil {
			FATAL("Failed to get selected rules: %v", err)
		}
	} else {
		FATAL("No tailored profile provided")
	}
	evalResultList := []*v1alpha1.ComplianceCheckResult{}
	// Process each selected rule
	for _, rule := range selectedRules {
		DBG("Processing rule: %s\n", rule.Name)
		// Fetch the resources based on the rule inputs, we will either use the pre-fetched resources or access the API server
		// Check if we have the resources in the pre-fetched resources
		var resourceMap map[string]interface{}

		if c.celConfig.ApiResourcePath == "" {
			LOG("Fetching resources from API server")
			// Fetch the resources from the API server
			collectedResources, warnings, err := c.FetchResources(rule)
			if err != nil {
				LOG("Error fetching resources: %v", err)
			}
			if len(warnings) > 0 {
				LOG("Warnings while fetching resources: %v", warnings)
			}
			resourceMap = map[string]interface{}{}
			for k, v := range collectedResources {
				resourceMap[k] = v
			}
		} else {
			LOG("Using pre-fetched resources")
			// Collect the necessary resources from the mounted directory based on rule inputs
			resourceMap = c.collectResourcesFromFiles(c.celConfig.ApiResourcePath, rule)
		}
		DBG("Collected resources: %v\n", resourceMap)
		// Create CEL declarations
		declsList := createCelDeclarations(resourceMap)
		// Create a CEL environment
		env := createCelEnvironment(declsList)
		// Compile and evaluate the CEL expression
		ast, err := compileCelExpression(env, rule.Expression)
		if err != nil {
			FATAL("Failed to compile CEL expression: %v", err)
		}
		result := evaluateCelExpression(env, ast, resourceMap, rule)
		if result.Status == v1alpha1.CheckResultFail {
			exitCode = 2
		} else if result.Status == v1alpha1.CheckResultError {
			exitCode = -1
		}
		evalResultList = append(evalResultList, &result)
	}
	// Save the scan result
	outputFilePath := filepath.Join(c.celConfig.CheckResultDir, "report.xml")
	saveScanResult(outputFilePath, evalResultList)
	// Check if we need to generate ComplianceCheckResult objects
	if c.celConfig.CCRGeneration {
		// TODO(@Vincent056): Generate ComplianceCheckResult objects
	}
	// Save the exit code to a file
	// We are matching the exit code to the openscap exit codes
	exitCodeFilePath := filepath.Join(c.celConfig.CheckResultDir, "exit_code")
	err := os.WriteFile(exitCodeFilePath, []byte(fmt.Sprintf("%d", exitCode)), 0644)
	if err != nil {
		FATAL("Failed to write exit code to file: %v", err)
	}
	os.Exit(0)
}
func (c *CelScanner) getTailoredProfile(namespace string) (*cmpv1alpha1.TailoredProfile, error) {
	tailoredProfile := &cmpv1alpha1.TailoredProfile{}
	tpKey := v1api.NamespacedName{Name: c.celConfig.Tailoring, Namespace: namespace}
	err := c.client.Get(context.TODO(), tpKey, tailoredProfile)
	if err != nil {
		return nil, err
	}
	return tailoredProfile, nil
}
func (c *CelScanner) getSelectedCustomRules(tp *cmpv1alpha1.TailoredProfile) ([]*cmpv1alpha1.CustomRule, error) {
	var selectedRules []*cmpv1alpha1.CustomRule
	for _, selection := range append(tp.Spec.EnableRules, append(tp.Spec.DisableRules, tp.Spec.ManualRules...)...) {
		for _, rule := range selectedRules {
			// make sure ruleKind is CustomRule
			if rule.Kind != "CustomRule" {
				return nil, fmt.Errorf("Rule '%s' is not a CustomRule", selection.Name)
			}
			if rule.Name == selection.Name {
				return nil, fmt.Errorf("Rule '%s' appears twice in selections", selection.Name)
			}
		}
		rule := &cmpv1alpha1.CustomRule{}
		ruleKey := v1api.NamespacedName{Name: selection.Name, Namespace: tp.Namespace}
		err := c.client.Get(context.TODO(), ruleKey, rule)
		if err != nil {
			return nil, fmt.Errorf("Fetching rule: %w", err)
		}
		selectedRules = append(selectedRules, rule)
	}
	return selectedRules, nil
}
func (c *CelScanner) collectResourcesFromFiles(resourceDir string, rule *cmpv1alpha1.CustomRule) map[string]interface{} {
	resultMap := make(map[string]interface{})
	if rule.Inputs != nil {
		for _, input := range rule.Inputs {
			if input.KubeResource == (cmpv1alpha1.KubeResource{}) {
				FATAL("Got empty KubeResource in rule input")
			}
			// Define the GroupVersionResource for the current input
			gvr := schema.GroupVersionResource{
				Group:    input.KubeResource.APIGroup,
				Version:  input.KubeResource.Version,
				Resource: input.KubeResource.Resource,
			}
			// Derive the resource path using a common function
			objPath := DeriveResourcePath(gvr, input.KubeResource.Namespace) + ".json"
			// Build the complete file path
			filePath := filepath.Join(resourceDir, objPath)
			// Read the file content
			fileContent, err := os.ReadFile(filePath)
			if err != nil {
				panic(fmt.Sprintf("Failed to read file %s: %v", filePath, err))
			}
			// check if input.resource contains /, if so, it is a subresource
			if strings.Contains(input.KubeResource.Resource, "/") {
				// Unmarshal JSON content into an unstructured object
				result := &unstructured.Unstructured{}
				err = json.Unmarshal(fileContent, &result)
				if err != nil {
					panic(fmt.Sprintf("Failed to parse JSON from file %s: %v", filePath, err))
				}
				resultMap[input.KubeResource.Name] = result
			} else {
				// Unmarshal JSON content into an unstructured list
				results := &unstructured.UnstructuredList{}
				err = json.Unmarshal(fileContent, &results)
				if err != nil {
					panic(fmt.Sprintf("Failed to parse JSON from file %s: %v", filePath, err))
				}
				resultMap[input.KubeResource.Name] = results
			}
		}
	}
	return resultMap
}
func createCelDeclarations(resultMap map[string]interface{}) []*expr.Decl {
	declsList := []*expr.Decl{}
	for k := range resultMap {
		declsList = append(declsList, decls.NewVar(k, decls.Dyn))
	}
	return declsList
}
func createCelEnvironment(declsList []*expr.Decl) *cel.Env {
	mapStrDyn := cel.MapType(cel.StringType, cel.DynType)
	jsonenvOpts := cel.Function("parseJSON",
		cel.MemberOverload("parseJSON_string",
			[]*cel.Type{cel.StringType}, mapStrDyn, cel.UnaryBinding(parseJSONString)))
	yamlenvOpts := cel.Function("parseYAML",
		cel.MemberOverload("parseYAML_string",
			[]*cel.Type{cel.StringType}, mapStrDyn, cel.UnaryBinding(parseYAMLString)))
	env, err := cel.NewEnv(
		cel.Declarations(declsList...), jsonenvOpts, yamlenvOpts,
	)
	if err != nil {
		panic(fmt.Sprintf("Failed to create CEL environment: %s", err))
	}
	return env
}
func compileCelExpression(env *cel.Env, expression string) (*cel.Ast, error) {
	ast, issues := env.Compile(expression)
	if issues.Err() != nil {
		return nil, fmt.Errorf("Failed to compile CEL expression: %s", issues.Err())
	}
	return ast, nil
}
func evaluateCelExpression(env *cel.Env, ast *cel.Ast, resourceMap map[string]interface{}, rule *cmpv1alpha1.CustomRule) v1alpha1.ComplianceCheckResult {
	evalVars := map[string]interface{}{}
	ruleResult := v1alpha1.ComplianceCheckResult{
		ID: rule.ID,
		ObjectMeta: metav1.ObjectMeta{
			Name:      rule.Name,
			Namespace: rule.Namespace,
		},
		Description:  rule.Description,
		Rationale:    rule.Rationale,
		Severity:     v1alpha1.ComplianceCheckResultSeverity(rule.Severity),
		Warnings:     []string{},
		Instructions: rule.Instructions,
		// TODO: populate the values used in the rule
	}
	for k, v := range resourceMap {
		// print debug log
		DBG("Evaluating variable %s: %v\n", k, v)
		evalVars[k] = toCelValue(v)
	}
	prg, err := env.Program(ast)
	if err != nil {
		panic(fmt.Sprintf("Failed to create CEL program: %s", err))
	}
	out, _, err := prg.Eval(evalVars)
	if err != nil {
		if strings.HasPrefix(err.Error(), "no such key:") {
			fmt.Printf("Warning: %s in %s\n", err, rule.Inputs[0].KubeResource.Resource)
			ruleResult.Warnings = append(ruleResult.Warnings, fmt.Sprintf("Warning: %s in %s\n", err, rule.Inputs[0].KubeResource.Resource))
			ruleResult.Status = v1alpha1.CheckResultError
			return ruleResult
		}
		panic(fmt.Sprintf("Failed to evaluate CEL expression: %s", err))
	}
	// TODO: handle CPE based on platform
	if out.Value() == false {
		ruleResult.Warnings = append(ruleResult.Warnings, fmt.Sprintf("Failed to evaluate CEL expression: %s", err))
		ruleResult.Status = v1alpha1.CheckResultFail
		fmt.Println(rule.ErrorMessage)
	} else {
		ruleResult.Status = v1alpha1.CheckResultPass
		fmt.Printf("%s: %v\n", rule.Title, out)
	}
	return ruleResult
}

func (c *CelScanner) FetchResources(rule *cmpv1alpha1.CustomRule) (map[string][]byte, []string, error) {
	figuredResourcePaths, err := c.FigureResources(rule)
	if err != nil {
		LOG("Error figuring resources: %v for rule: %s", err, rule.Name)
		return nil, nil, err
	}

	found, warnings, err := fetch(context.Background(), getStreamerFn, c.resourceFetcherClients, figuredResourcePaths)
	if err != nil {
		return nil, warnings, err
	}
	// print the found resources
	for k, v := range found {
		LOG("Found resource: %s\n", k)
		LOG("Resource content: %s\n", v)
	}

	return found, warnings, nil
}

// we will find resource and return the resource
func (c *CelScanner) FigureResources(rule *cmpv1alpha1.CustomRule) ([]utils.ResourcePath, error) {
	// Initial set of resources to fetch
	found := []utils.ResourcePath{}

	DBG("Processing rule: %s\n", rule.Name)
	DBG("Rule inputs: %v\n", rule.Inputs)
	for _, universalInput := range rule.Inputs {
		input := universalInput.KubeResource
		gvr := schema.GroupVersionResource{
			Group:    input.APIGroup,
			Version:  input.Version,
			Resource: input.Resource,
		}
		// Derive the resource path using the common function
		objPath := DeriveResourcePath(gvr, input.Namespace)
		found = append(found, utils.ResourcePath{
			ObjPath:  objPath,
			DumpPath: objPath + ".json",
		})
	}
	DBG("resources: %v\n", found)
	return found, nil
}

func saveScanResult(filePath string, resultsList []*v1alpha1.ComplianceCheckResult) {
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
func parseJSONString(val ref.Val) ref.Val {
	str := val.(types.String)
	decodedVal := map[string]interface{}{}
	err := json.Unmarshal([]byte(str), &decodedVal)
	if err != nil {
		return types.NewErr("failed to decode '%v' in parseJSON: %w", str, err)
	}
	r, err := types.NewRegistry()
	if err != nil {
		return types.NewErr("failed to create a new registry in parseJSON: %w", err)
	}
	return types.NewDynamicMap(r, decodedVal)
}
func parseYAMLString(val ref.Val) ref.Val {
	str := val.(types.String)
	decodedVal := map[string]interface{}{}
	err := yaml.Unmarshal([]byte(str), &decodedVal)
	if err != nil {
		return types.NewErr("failed to decode '%v' in parseYAML: %w", str, err)
	}
	r, err := types.NewRegistry()
	if err != nil {
		return types.NewErr("failed to create a new registry in parseYAML: %w", err)
	}
	return types.NewDynamicMap(r, decodedVal)
}
func toCelValue(u interface{}) interface{} {
	if unstruct, ok := u.(*unstructured.Unstructured); ok {
		return unstruct.Object
	}
	if unstructList, ok := u.(*unstructured.UnstructuredList); ok {
		list := []interface{}{}
		for _, item := range unstructList.Items {
			list = append(list, item.Object)
		}
		return map[string]interface{}{
			"items": list,
		}
	}
	return nil
}
func getCelScannerClient(scheme *runtime.Scheme) (client.Client, error) {
	config := getConfig()
	client, err := client.New(config, client.Options{
		Scheme: scheme,
	})
	if err != nil {
		return nil, err
	}
	return client, nil
}
