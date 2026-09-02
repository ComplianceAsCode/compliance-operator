package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var rootCmd = &cobra.Command{
	Use:   "oc-compliance",
	Short: "A set of utilities that come along with the compliance-operator.",
	Long:  `A set of utilities that come along with the compliance-operator.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprint(os.Stderr, "You must specify a sub-command.\n\n")
		return cmd.Usage()
	},
}

func main() {
	flags := pflag.NewFlagSet("oc-compliance", pflag.ExitOnError)
	pflag.CommandLine = flags

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
