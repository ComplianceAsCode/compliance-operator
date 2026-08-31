package main

import (
	"fmt"
	"os"

	"github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/fetchstigresults"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func init() {
	cmd := NewCmdFetchStigResults(genericclioptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr})
	rootCmd.AddCommand(cmd)
}

func NewCmdFetchStigResults(streams genericclioptions.IOStreams) *cobra.Command {
	examples := `
  # Generate a single combined DISA STIG Viewer XCCDF result file for the "stig" ScanSettingBinding
  %[1]s %[2]s stig -o stig-results/

  # Emit one result file per scan instead of a combined file
  %[1]s %[2]s stig --per-scan -o stig-results/

  # Generate a result file for only the "rhcos4-stig-master" scan of the binding
  %[1]s %[2]s stig --scan rhcos4-stig-master -o stig-results/
`

	longDesc := `Generate DISA STIG Viewer XCCDF result files from the ComplianceCheckResults
produced by a ScanSettingBinding.

The compliance content carries the srg-stig-tools reference for each STIG rule,
which the Compliance Operator surfaces on every result as the
'control.compliance.openshift.io/STIG-RULE' annotation (the SV-*_rule id). This
command reads those results and rewrites each rule id to its STIG reference,
writing XCCDF results into the output directory. Where a single STIG rule is
covered by more than one check, the worst status wins.

By default every scan is collapsed into a single combined file (named after the
binding); because STIG rule ids are globally unique, that file can be imported
against either the platform or node STIG in DISA STIG Viewer. Use --per-scan to
instead emit one file per scan (e.g. ocp4-stig.xml, rhcos4-stig-master.xml), or
--scan to restrict output to a single named scan.`

	ctx := fetchstigresults.NewFetchStigResultsContext(streams)
	cmd := &cobra.Command{
		Use:          "fetch-stig-results <scansettingbinding-name> -o <output-dir>",
		Short:        "Generate DISA STIG Viewer XCCDF results from a ScanSettingBinding",
		Long:         longDesc,
		Example:      fmt.Sprintf(examples, "oc compliance", "fetch-stig-results"),
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			if err := ctx.Complete(c, args); err != nil {
				return err
			}
			if err := ctx.Validate(); err != nil {
				return err
			}
			return ctx.Run()
		},
	}

	ctx.ConfigFlags.AddFlags(cmd.Flags())
	cmd.Flags().StringVarP(&ctx.OutputPath, "output", "o", "",
		"The directory to write the XCCDF result file(s) to (required)")
	cmd.Flags().BoolVar(&ctx.PerScan, "per-scan", false,
		"Emit one result file per scan instead of a single combined file")
	cmd.Flags().StringVar(&ctx.Scan, "scan", "",
		"Restrict output to a single named scan of the binding")
	return cmd
}
