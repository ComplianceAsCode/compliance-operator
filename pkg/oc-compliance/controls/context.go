package controls

import (
	"fmt"

	"github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/common"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

const AllBenchmarks = "all"

type ControlsContext struct {
	common.CommandContext
	Benchmark string
}

func NewControlsContext(streams genericclioptions.IOStreams) *ControlsContext {
	return &ControlsContext{
		CommandContext: common.CommandContext{
			ConfigFlags: genericclioptions.NewConfigFlags(true),
			IOStreams:   streams,
		},
	}
}

// Validate ensures that all required arguments and flag values are provided
func (o *ControlsContext) Validate() error {
	objref, err := common.ValidateObjectArgs(o.Args)
	if err != nil {
		return err
	}

	switch objref.Type {
	case common.Profile:
		o.Helper = NewProfileHelper(o.Kuser, objref.Name, o.IOStreams, o.Benchmark)
	default:
		return fmt.Errorf("Invalid object type for this command")
	}
	return nil
}

func (o *ControlsContext) Run() error {
	return o.Helper.Handle()
}
