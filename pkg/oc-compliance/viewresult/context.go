package viewresult

import (
	"fmt"

	"github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/common"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

type ViewResultContext struct {
	common.CommandContext
}

func NewViewResultContext(streams genericclioptions.IOStreams) *ViewResultContext {
	return &ViewResultContext{
		CommandContext: common.CommandContext{
			ConfigFlags: genericclioptions.NewConfigFlags(true),
			IOStreams:   streams,
		},
	}
}

// Validate ensures that all required arguments and flag values are provided
func (o *ViewResultContext) Validate() error {
	if len(o.Args) < 1 {
		return fmt.Errorf("You need to select at least one result")
	}

	o.Helper = NewResultHelper(o.Kuser, o.Args[0], o.IOStreams)
	return nil
}

func (o *ViewResultContext) Run() error {
	return o.Helper.Handle()
}
