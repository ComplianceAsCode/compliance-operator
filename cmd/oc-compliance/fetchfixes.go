package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	fetchfixes "github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/fetchfixes"
)

func init() {
	fetchFixesCmd := NewCmdFetchFixes(genericclioptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr})
	rootCmd.AddCommand(fetchFixesCmd)
}

func NewCmdFetchFixes(streams genericclioptions.IOStreams) *cobra.Command {
	var (
		usageExamples = `
  # Fetch from a rule named "ocp4-api-server-encryption-provider-cipher" into /tmp
  %[1]s %[2]s rule ocp4-api-server-encryption-provider-cipher -o /tmp

  # Fetch from a profile named "ocp4-cis" into /tmp
  %[1]s %[2]s profile ocp4-cis -o /tmp

  # Fetch from a complianceRemediation named ocp4-cis-api-server-encryption-provider-cipher into /tmp
  %[1]s %[2]s complianceremediation ocp4-cis-api-server-encryption-provider-cipher -o /tmp
`
	)

	o := fetchfixes.NewFetchFixesContext(streams)

	cmd := &cobra.Command{
		Use:   "fetch-fixes {rule | profile | complianceremediation } <resource-name> -o <output path>",
		Short: "Download the fixes/remediations",
		Long: `'fetch-fixes' fetches the fixes/remediations from a Rule, Profile, or ComplianceRemediation.

This command allows you to download the proposed fixes from a Rule, Profile, or
ComplianceRemediation into a specified directory.`,
		Example:      fmt.Sprintf(usageExamples, "oc compliance", "fetch-fixes"),
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

	cmd.Flags().StringVarP(&o.OutputPath, "output", "o", ".", "The path where you want to persist the fix objects to")
	cmd.Flags().StringSliceVarP(&o.MCRoles, "mc-roles", "", []string{"worker", "master"},
		"If the remediation(s) are MachineConfig objects, render them with the following roles")
	cmd.Flags().StringVarP(&o.ExtraManifestBuildType, "manifest-prepare", "", "default",
		"Prepare the manifests for another system to use them. e.g. a GitOps engine.\n"+
			"Available Options:\n"+
			"\t* 'default'\t- does nothing.\n"+
			"\t* 'ArgoCD'\t- prepares the manifest for ArgoCD (OpenShift GitOps)\n")
	o.ConfigFlags.AddFlags(cmd.Flags())

	return cmd
}
