package main

import (
	"fmt"
	"os"

	"github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/controls"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func init() {
	controlsCmd := NewCmdControls(genericclioptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr})
	rootCmd.AddCommand(controlsCmd)
}

func NewCmdControls(streams genericclioptions.IOStreams) *cobra.Command {
	var (
		controlsExamples = `
  # View controls for the "ocp4-cis-node" profile
  %[1]s %[2]s profile ocp4-cis-node
`
	)

	ctx := controls.NewControlsContext(streams)
	cmd := &cobra.Command{
		Use:          "controls profile <profile-name>",
		Short:        "Get a report of what controls you're complying with",
		Long:         "Get a report of what controls you're complying with",
		Example:      fmt.Sprintf(controlsExamples, "oc compliance", "controls"),
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
	cmd.Flags().StringVarP(&ctx.Benchmark, "benchmark", "b", controls.AllBenchmarks,
		"The benchmark we want to retrieve the controls for")
	return cmd
}
