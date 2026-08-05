package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/viewresult"
)

func init() {
	viewresultCmd := NewCmdViewResult(genericclioptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr})
	rootCmd.AddCommand(viewresultCmd)
}

func NewCmdViewResult(streams genericclioptions.IOStreams) *cobra.Command {
	var (
		rerunExamples = `
  # Viewing the ComplianceCheckResult named "ocp4-cis-scheduler-no-bind-address"
  %[1]s %[2]s ocp4-cis-scheduler-no-bind-address
`
	)

	ctx := viewresult.NewViewResultContext(streams)
	cmd := &cobra.Command{
		Use:          "view-result <result-name>",
		Short:        "View a ComplianceCheckResult",
		Long:         `'view-result' exposes more information about a ComplianceCheckResult.`,
		Example:      fmt.Sprintf(rerunExamples, "oc compliance", "view-result"),
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
