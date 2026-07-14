// celctl — a self-contained CEL rule utility for Kubernetes compliance checks.
//
// Replaces the cel-rpc-server MCP server for the create/validate/run loop:
//   - evaluates CEL locally with cel-go (the same engine the scanner uses)
//   - runs rules against a live cluster via kubectl
//   - validates ComplianceAsCode/content rules natively (see cac.go)
//
// Rules live in the ComplianceAsCode/content repo. No server, no container,
// no AI keys.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/ComplianceAsCode/compliance-sdk/pkg/scanner"
)

// newFlags returns a FlagSet that prints a contextual usage line on error.
func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	return fs
}

// reorderArgs moves positional args to the end so flags may appear after them.
// Go's flag package stops at the first non-flag token; this lets users write
// `cac test <dir> --cases x` as well as `cac test --cases x <dir>`. Assumes flags
// take values in `--flag value` or `--flag=value` form (no standalone bools).
func reorderArgs(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flags = append(flags, args[i+1])
				i++
			}
		} else {
			pos = append(pos, a)
		}
	}
	return append(flags, pos...)
}

// ----- ad-hoc test-case model (used by `verify --expr --test`) -----

type TestCase struct {
	Description    string `json:"description,omitempty"`
	ExpectedResult bool   `json:"expected_result"`
	// TestData maps a variable name to its data. Accepts either a JSON string
	// (cel-rpc-server format) or an inline JSON object — see UnmarshalJSON.
	TestData map[string]json.RawMessage `json:"test_data"`
}

// ----- CEL evaluation core -----

// evalExpr compiles expr with the given variables declared as dynamic, then
// evaluates it. The boolean result is returned. vars values must already be
// decoded JSON (map[string]interface{}, []interface{}, float64, string, ...).
//

// decodeTestData turns a test case's TestData (each value a JSON string or
// inline object) into decoded Go values ready for CEL.
func decodeTestData(td map[string]json.RawMessage) (map[string]interface{}, error) {
	vars := map[string]interface{}{}
	for name, raw := range td {
		v, err := decodeMaybeString(raw)
		if err != nil {
			return nil, fmt.Errorf("input %q: %w", name, err)
		}
		vars[name] = v
	}
	return vars, nil
}

// decodeMaybeString accepts raw that is either a JSON string containing JSON
// (e.g. "{\"items\":[]}") or an inline JSON value, and returns the decoded value.
func decodeMaybeString(raw json.RawMessage) (interface{}, error) {
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "\"") {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		var v interface{}
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			return nil, fmt.Errorf("value is a string but not valid JSON: %w", err)
		}
		return v, nil
	}
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// ----- commands -----

func cmdVerify(args []string) int {
	fs := newFlags("verify")
	expr := fs.String("expr", "", "CEL expression (required)")
	dataPath := fs.String("test", "", "path to a JSON file with an array of test cases (required)")
	fs.Parse(reorderArgs(args))
	if *expr == "" || *dataPath == "" {
		return fail("usage: celctl verify --expr <cel> --test <cases.json>  (for cac-content rules use `celctl cac test`)")
	}
	var testCases []TestCase
	if err := loadJSON(*dataPath, &testCases); err != nil {
		return fail("load test cases: %v", err)
	}
	if len(testCases) == 0 {
		return fail("no test cases to run")
	}

	pass, total := 0, len(testCases)
	for i, tc := range testCases {
		desc := tc.Description
		if desc == "" {
			desc = fmt.Sprintf("test case %d", i+1)
		}
		vars, err := decodeTestData(tc.TestData)
		if err != nil {
			fmt.Printf("  FAIL %s — bad test data: %v\n", desc, err)
			continue
		}
		got, err := evalExpr(*expr, vars)
		if err != nil {
			fmt.Printf("  FAIL %s — %v\n", desc, err)
			continue
		}
		if got == tc.ExpectedResult {
			pass++
			fmt.Printf("  PASS %s — got %v (expected %v)\n", desc, got, tc.ExpectedResult)
		} else {
			fmt.Printf("  FAIL %s — got %v, expected %v\n", desc, got, tc.ExpectedResult)
		}
	}
	fmt.Printf("\n%d/%d passed\n", pass, total)
	if pass != total {
		return 1
	}
	return 0
}

func cmdEval(args []string) int {
	fs := newFlags("eval")
	expr := fs.String("expr", "", "CEL expression (required)")
	var datas multiFlag
	fs.Var(&datas, "data", "variable binding name=path.json or name=@- for stdin (repeatable)")
	fs.Parse(reorderArgs(args))
	if *expr == "" {
		return fail("--expr is required")
	}
	vars := map[string]interface{}{}
	for _, d := range datas {
		name, path, ok := strings.Cut(d, "=")
		if !ok {
			return fail("bad --data %q (want name=path.json)", d)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return fail("read %s: %v", path, err)
		}
		v, err := decodeMaybeString(raw)
		if err != nil {
			return fail("decode %s: %v", path, err)
		}
		vars[name] = v
	}
	got, err := evalExpr(*expr, vars)
	if err != nil {
		return fail("%v", err)
	}
	fmt.Printf("%v\n", got)
	if !got {
		return 1
	}
	return 0
}

func cmdLive(args []string) int {
	fs := newFlags("live")
	expr := fs.String("expr", "", "CEL expression (required)")
	var inputs multiFlag
	fs.Var(&inputs, "input", "name=[group/]version/resource[:namespace] (repeatable)")
	fs.Parse(reorderArgs(args))
	if *expr == "" || len(inputs) == 0 {
		return fail("usage: celctl live --expr <cel> --input name=[group/]version/resource[:ns] ...  (for cac-content rules use `celctl cac live`)")
	}
	sdkInputs := make([]scanner.Input, 0, len(inputs))
	for _, in := range inputs {
		parsed, err := parseInputSpec(in)
		if err != nil {
			return fail("%v", err)
		}
		sdkInputs = append(sdkInputs, parsed)
	}
	fetcher, err := newKubeFetcher()
	if err != nil {
		return fail("%v", err)
	}
	out, err := runRule(adhocRule{id: "live", expr: *expr, inputs: sdkInputs}, fetcher)
	if err != nil {
		return fail("%v", err)
	}
	if out.status != "PASS" && out.status != "FAIL" {
		return fail("%s: %s", out.status, out.errMsg)
	}
	if w := firstNoSuchKeyWarning(out.warnings); w != "" {
		fmt.Printf("  WARNING: %s (the scanner maps this to FAIL)\n", w)
	}
	if out.pass() {
		fmt.Printf("\nPASS — cluster satisfies the expression\n")
		return 0
	}
	fmt.Printf("\nFAIL — cluster does not satisfy the expression\n")
	return 1
}

// ----- rule library -----

// ----- discovery (thin kubectl wrappers) -----

func cmdDiscover(args []string) int {
	out, err := runKubectl("api-resources", "--verbs=list", "-o", "wide")
	if err != nil {
		return fail("%v", err)
	}
	fmt.Print(out)
	return 0
}

func cmdSamples(args []string) int {
	fs := newFlags("samples")
	ns := fs.String("n", "", "namespace")
	max := fs.Int("max", 3, "max samples")
	fs.Parse(reorderArgs(args))
	res := fs.Arg(0)
	if res == "" {
		return fail("usage: celctl samples <resource> [-n ns] [--max N]")
	}
	kargs := []string{"get", res, "-o", "json"}
	if *ns != "" {
		kargs = append(kargs, "-n", *ns)
	} else {
		kargs = append(kargs, "-A")
	}
	out, err := runKubectl(kargs...)
	if err != nil {
		return fail("%v", err)
	}
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return fail("%v", err)
	}
	if len(list.Items) > *max {
		list.Items = list.Items[:*max]
	}
	b, _ := json.MarshalIndent(map[string]interface{}{"items": list.Items}, "", "  ")
	fmt.Println(string(b))
	return 0
}

// ----- helpers -----

func runKubectl(args ...string) (string, error) {
	cmd := exec.Command("kubectl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("kubectl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func parseInputSpec(s string) (adhocInput, error) {
	name, rest, ok := strings.Cut(s, "=")
	if !ok {
		return adhocInput{}, fmt.Errorf("bad --input %q (want name=[group/]version/resource[:namespace])", s)
	}
	gvr, ns, _ := strings.Cut(rest, ":")
	parts := strings.Split(gvr, "/")
	spec := adhocInputSpec{namespace: ns}
	switch len(parts) {
	case 2: // version/resource
		spec.version, spec.resource = parts[0], parts[1]
	case 3: // group/version/resource
		spec.group, spec.version, spec.resource = parts[0], parts[1], parts[2]
	default:
		return adhocInput{}, fmt.Errorf("bad gvr %q in --input (want [group/]version/resource)", gvr)
	}
	return adhocInput{name: name, spec: spec}, nil
}

func loadJSON(path string, v interface{}) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// flag helpers

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func fail(format string, a ...interface{}) int {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	return 2
}

func usage() {
	fmt.Print(`celctl — CEL rule authoring and unit-test utility for ComplianceAsCode/content

Usage:
  ComplianceAsCode/content (cac-content) rules — the primary workflow.
  Operate on a rule dir or its cel/shared.yml:
  celctl cac lint  <rule-dir>                       Compile + empty-eval; catches list/.items bugs
  celctl cac scaffold <rule-dir> [--from-cluster]   Generate cel/tests fixtures (real objects + provenance)
  celctl cac test  <rule-dir>                       Unit-test cel/tests fixtures (or --cases f | --mock name=f)
  celctl cac live  <rule-dir>                       Fetch + evaluate against the cluster

  celctl skill install [--dir D] [--force]          Install the embedded Claude Code skill
  celctl skill status                               Show installed vs binary skill version

  Ad-hoc expression helpers:
  celctl eval     --expr '<cel>' --data v=v.json    Evaluate once, print bool
  celctl verify   --expr '<cel>' --test cases.json  Run ad-hoc test cases
  celctl live     --expr '<cel>' --input pods=v1/pods:default

  celctl discover                                   kubectl api-resources
  celctl samples  <resource> [-n ns] [--max N]      Sample objects from cluster

CEL note: list inputs bind as {items:[...]}; iterate with <var>.items.all(x, ...) / .exists(...).
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var code int
	switch cmd {
	case "verify", "validate":
		code = cmdVerify(args)
	case "eval":
		code = cmdEval(args)
	case "live":
		code = cmdLive(args)
	case "cac":
		code = cmdCac(args)
	case "skill":
		code = cmdSkill(args)
	case "discover":
		code = cmdDiscover(args)
	case "samples":
		code = cmdSamples(args)
	case "-h", "--help", "help":
		usage()
		code = 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		code = 2
	}
	os.Exit(code)
}
