package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	fetchraw "github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/fetchraw"
)

func init() {
	fetchRawCmd := NewCmdFetchRaw(genericclioptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr})
	rootCmd.AddCommand(fetchRawCmd)
}

func NewCmdFetchRaw(streams genericclioptions.IOStreams) *cobra.Command {
	var (
		usageExamples = `
  # Fetch from compliancescan named "myscan" into /tmp
  %[1]s %[2]s compliancescan myscan -o /tmp

  # Fetch from compliancesuite named "mysuite" into /tmp
  %[1]s %[2]s compliancesuite mysuite -o /tmp

  # Fetch from scansettingbinding named "mybinding" into /tmp
  %[1]s %[2]s scansettingbindings mybinding -o /tmp
`
	)

	o := fetchraw.NewFetchRawOptions(streams)

	cmd := &cobra.Command{
		Use:   "fetch-raw {compliancescan | compliancesuite | scansettingbindings} <resource-name> -o <output path>",
		Short: "Download raw compliance results",
		Long: `'fetch-raw' fetches the raw results for a scan or set of scans.

This command allows you to download archives of the raw (ARF) results from a
ComplianceScan, ComplianceSuite, or ScanSettingBinding to a specified directory.`,
		Example:      fmt.Sprintf(usageExamples, "oc compliance", "fetch-raw"),
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			if err := o.Complete(c, args); err != nil {
				return err
			}
			if err := o.Validate(); err != nil {
				return err
			}
			if err := o.Run(); err != nil {
				return err
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&o.OutputPath, "output", "o", ".", "The path where you want to persist the raw results to")
	cmd.Flags().StringVarP(&o.Image, "image", "i", "registry.access.redhat.com/ubi8/ubi:latest",
		"The container image to use to fetch the raw results from the compliance scan. Must contain the cp and tar commands.")
	cmd.Flags().BoolVar(&o.HTML, "html", false, "Whether to render the raw results to HTML (Requires the 'oscap' command)")
	o.ConfigFlags.AddFlags(cmd.Flags())

	return cmd
}
