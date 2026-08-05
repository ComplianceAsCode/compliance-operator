package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	bind "github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/bind"
)

func init() {
	bindCmd := NewCmdBind(genericclioptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr})
	rootCmd.AddCommand(bindCmd)
}

func NewCmdBind(streams genericclioptions.IOStreams) *cobra.Command {
	var (
		usageExamples = `
  # Create a ScanSettngBinding
  %[1]s %[2]s -N <binding name> [-S <scansetting name>] <objtype/objname> [..<objtype/objname>]

  # Display a ScanSettingBinding
  %[1]s %[2]s --dry-run -N <binding name> [-S <scansetting name>] <objtype/objname> [..<objtype/objname>]

  # Example: Creating a ScanSettingBinding named "mybinding" that applies the "default" ScanSettings to the standard CIS Profiles.
  %[1]s %[2]s -N mybinding profile/ocp4-cis profile/ocp4-cis-node

  # Example: Creating a ScanSettingBinding named "mybinding" that applies the "default-auto-apply" ScanSettings to a tailored CIS Profile.
  %[1]s %[2]s -N mybinding -S default-auto-apply tailoredprofile/ocp4-cis-node-tailored
`
	)

	o := bind.NewBindContext(streams)

	cmd := &cobra.Command{
		Use:   "bind [--dry-run] -N <binding name> [-S <scansetting name>] <objtype/objname> [..<objtype/objname>]",
		Short: "Creates a ScanSettingBinding for the given parameters",
		Long: `'bind' will take the given parameters and create a ScanSettingBinding object.

These objects will take the given ScanSettings and bind them to the given
Profiles and TailoredProfiles.

If the -S option is not provided, then the ScanSettingBinding will bind the
"default" ScanSetting (an hourly scan on worker and master nodes).`,
		Example:      fmt.Sprintf(usageExamples, "oc compliance", "bind"),
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

	cmd.Flags().StringVarP(&o.Settings, "settings", "S", "default", "The scan settings to bind the Profiles/TailoredProfiles to")
	cmd.Flags().StringVarP(&o.Name, "name", "N", "", "The name of the binding to create")
	cmd.Flags().BoolVar(&o.DryRun, "dry-run", false, "Output the scansettingbinding that would be created")
	o.ConfigFlags.AddFlags(cmd.Flags())

	return cmd
}
