package fetchstigresults

import (
	"fmt"

	"github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/common"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// FetchStigResultsContext holds the state for the fetch-stig-results subcommand.
type FetchStigResultsContext struct {
	common.CommandContext
	// OutputPath is the directory the generated XCCDF result files are written
	// to (one file per scan).
	OutputPath string
	// Scan, when set, restricts output to the single named scan of the binding.
	Scan string
	// PerScan emits one file per scan instead of a single combined file.
	PerScan bool
}

func NewFetchStigResultsContext(streams genericclioptions.IOStreams) *FetchStigResultsContext {
	return &FetchStigResultsContext{
		CommandContext: common.CommandContext{
			ConfigFlags: genericclioptions.NewConfigFlags(true),
			IOStreams:   streams,
		},
	}
}

// Validate ensures that all required arguments and flag values are provided.
func (o *FetchStigResultsContext) Validate() error {
	if len(o.Args) != 1 {
		return fmt.Errorf("You need to specify exactly one ScanSettingBinding name")
	}
	if o.OutputPath == "" {
		return fmt.Errorf("You need to specify an output directory with --output/-o")
	}
	if o.Scan != "" && o.PerScan {
		return fmt.Errorf("--scan and --per-scan are mutually exclusive")
	}

	o.Helper = NewScanSettingBindingHelper(o.Kuser, o.Args[0], o.OutputPath, o.Scan, o.PerScan, o.IOStreams)
	return nil
}

func (o *FetchStigResultsContext) Run() error {
	return o.Helper.Handle()
}
