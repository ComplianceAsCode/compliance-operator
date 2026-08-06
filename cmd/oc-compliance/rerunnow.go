package main

import (
	"fmt"
	"os"

	"github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/rerunnow"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func init() {
	rerunNowCmd := NewCmdRerunNow(genericclioptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr})
	rootCmd.AddCommand(rerunNowCmd)
}

func NewCmdRerunNow(streams genericclioptions.IOStreams) *cobra.Command {
	var (
		rerunExamples = `
  # Re-run an individual ComplianceScan named "ocp4-cis"
  %[1]s %[2]s compliancescan ocp4-cis

  # Re-run all scans in a ComplianceSuite named "mysuite"
  %[1]s %[2]s compliancesuite mysuite

  # Re-run all ComplianceSuites bound by the ScanSettingBinding named "mybinding"
  %[1]s %[2]s scansettingbindings mybinding
`
	)

	ctx := rerunnow.NewReRunNowContext(streams)
	cmd := &cobra.Command{
		Use:          "rerun-now {compliancescan | compliancesuite | scansettingbindings} <object-name>",
		Short:        "Force a re-scan for one or more ComplianceScans",
		Long:         `'rerun-now' forces a ComplianceScan or set of ComplianceScans to be retriggered.`,
		Example:      fmt.Sprintf(rerunExamples, "oc compliance", "rerun-now"),
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			if err := ctx.Complete(c, args); err != nil {
				return err
			}
			if err := ctx.Validate(); err != nil {
				return err
			}
			if err := ctx.Run(); err != nil {
				return err
			}

			return nil
		},
	}

	ctx.ConfigFlags.AddFlags(cmd.Flags())
	return cmd
}
