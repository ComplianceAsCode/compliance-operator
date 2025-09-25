package controller

import (
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/customrule"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/metrics"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

func init() {
	// AddToManagerFuncs is a list of functions to create controllers and add them to a manager.
	AddToManagerFuncs = append(AddToManagerFuncs, func(mgr manager.Manager, met *metrics.Metrics, _ utils.CtlplaneSchedulingInfo, _ *kubernetes.Clientset) error {
		return customrule.Add(mgr)
	})
}
