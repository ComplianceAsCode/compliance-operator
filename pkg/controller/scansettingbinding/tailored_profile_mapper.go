package scansettingbinding

import (
	"context"
	"github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type tailoredProfileMapper struct {
	client.Client
}

func (s *tailoredProfileMapper) Map(ctx context.Context, obj client.Object) []reconcile.Request {
	var requests []reconcile.Request

	ssbList := v1alpha1.ScanSettingBindingList{}
	err := s.List(ctx, &ssbList, &client.ListOptions{})
	if err != nil {
		return requests
	}

	for _, ssb := range ssbList.Items {
		add := false

		for _, profRef := range ssb.Profiles {
			if profRef.Kind != "TailoredProfile" {
				continue
			}

			if profRef.Name != obj.GetName() {
				continue
			}

			add = true
			break
		}

		if add == false {
			continue
		}

		objKey := types.NamespacedName{
			Name:      ssb.GetName(),
			Namespace: ssb.GetNamespace(),
		}
		requests = append(requests, reconcile.Request{NamespacedName: objKey})
	}

	return requests
}
