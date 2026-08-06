package fetchfixes

import (
	"fmt"
	"os"

	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/common"
	"github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/fetchfixes/emb"
)

type FetchFixesContext struct {
	common.CommandContext

	OutputPath string
	// MachineConfig roles
	MCRoles                []string
	ExtraManifestBuildType string
	EMB                    emb.ExtraManifestBuilder
}

func NewFetchFixesContext(streams genericclioptions.IOStreams) *FetchFixesContext {
	return &FetchFixesContext{
		CommandContext: common.CommandContext{
			ConfigFlags: genericclioptions.NewConfigFlags(true),
			IOStreams:   streams,
		},
	}
}

// Validate ensures that all required arguments and flag values are provided
func (o *FetchFixesContext) Validate() error {
	finfo, err := os.Stat(o.OutputPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("The directory at path '%s' doesn't exist", o.OutputPath)
	}

	if !finfo.IsDir() {
		return fmt.Errorf("The output path must be a directory")
	}

	switch o.ExtraManifestBuildType {
	case emb.NoopBuilderName:
		o.EMB = emb.NewNoopManifestBuilder()
	case emb.ArgoCDBuilderName:
		o.EMB = emb.NewArgoCDManifestBuilder()
	default:
		return fmt.Errorf("Invalid prepare-manifest value. should be: 'default' or 'ArgoCD'")
	}

	objref, err := common.ValidateObjectArgs(o.Args)
	if err != nil {
		return err
	}

	switch objref.Type {
	case common.Rule:
		o.Helper = NewRuleHelper(o.Kuser, objref.Name, o.OutputPath, o.MCRoles, o.EMB, o.IOStreams)
	case common.Profile:
		o.Helper = NewProfileHelper(o.Kuser, objref.Name, o.OutputPath, o.MCRoles, o.EMB, o.IOStreams)
	case common.ComplianceRemediation:
		o.Helper = NewComplianceRemediationHelper(o.Kuser, objref.Name, o.OutputPath, o.MCRoles, o.EMB, o.IOStreams)
	default:
		return fmt.Errorf("Invalid object type for this command")
	}
	return nil
}

func (o *FetchFixesContext) Run() error {
	if err := o.Helper.Handle(); err != nil {
		return err
	}
	return o.EMB.FlushManifests(o.OutputPath, o.MCRoles)
}
