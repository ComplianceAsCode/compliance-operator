package compliancescan

import (
	"context"
	"reflect"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/common"
)

const (
	// Names of the operator-managed operand NetworkPolicies.
	networkPolicyDefaultDeny         = "compliance-operator-operands-default-deny"
	networkPolicyAllowEgress         = "compliance-operator-operands-allow-egress"
	networkPolicyResultServerIngress = "compliance-operator-resultserver-allow-ingress"

	// hostNetworkNamespaceLabel is the label OVN-Kubernetes places on the
	// namespace that represents host-network traffic. Selecting it admits
	// host-networked node-scan scanner pods to the result server, since
	// NetworkPolicy cannot select host-network pods directly.
	hostNetworkNamespaceLabel = "policy-group.network.openshift.io/host-network"
)

// operandPodSelector selects every operand pod carrying the NetworkPolicy
// marker label.
func operandPodSelector() metav1.LabelSelector {
	return metav1.LabelSelector{
		MatchLabels: map[string]string{compv1alpha1.NetworkPolicyOperandLabel: ""},
	}
}

// defaultDenyNetworkPolicy denies all ingress and egress for operand pods. The
// allow policies reopen only what the operands need.
func defaultDenyNetworkPolicy(ns string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      networkPolicyDefaultDeny,
			Namespace: ns,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: operandPodSelector(),
			// With both policy types set and no rules below, this denies all
			// ingress and egress; the allow policies add traffic back.
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
		},
	}
}

// allowEgressNetworkPolicy allows all egress from operand pods. Egress cannot be
// meaningfully restricted here: the API server is not selectable by
// NetworkPolicy, and scanner pods make arbitrary external egress when fetching
// remote SCAP resources. A single empty egress rule allows all egress, which
// also subsumes DNS.
func allowEgressNetworkPolicy(ns string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      networkPolicyAllowEgress,
			Namespace: ns,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: operandPodSelector(),
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress:      []networkingv1.NetworkPolicyEgressRule{{}},
		},
	}
}

// resultServerIngressNetworkPolicy allows scanner pods to reach the result
// server on its listening port. Platform-scan scanners run on the pod network
// and are selected directly; host-networked node-scan scanners are admitted via
// the OVN host-network namespace, since NetworkPolicy cannot select host-network
// pods. mTLS on the result server remains the real authentication boundary.
func resultServerIngressNetworkPolicy(ns string) *networkingv1.NetworkPolicy {
	tcp := corev1.ProtocolTCP
	port := intstr.FromInt32(ResultServerPort)
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      networkPolicyResultServerIngress,
			Namespace: ns,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{WorkloadLabel: WorkloadResultServer},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{WorkloadLabel: WorkloadScanner},
							},
						},
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{hostNetworkNamespaceLabel: ""},
							},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: &tcp, Port: &port},
					},
				},
			},
		},
	}
}

// operandNetworkPolicies returns the full set of operator-managed operand
// NetworkPolicies for the given namespace.
func operandNetworkPolicies(ns string) []*networkingv1.NetworkPolicy {
	return []*networkingv1.NetworkPolicy{
		defaultDenyNetworkPolicy(ns),
		allowEgressNetworkPolicy(ns),
		resultServerIngressNetworkPolicy(ns),
	}
}

// reconcileNetworkPolicies ensures the operand NetworkPolicies exist and match
// the desired spec. It uses get-then-create/update (no list or watch), matching
// the operator's RBAC grant, and is idempotent and safe to call on every
// reconcile.
func (r *ReconcileComplianceScan) reconcileNetworkPolicies(ctx context.Context, logger logr.Logger) error {
	ns := common.GetComplianceOperatorNamespace()
	for _, desired := range operandNetworkPolicies(ns) {
		if err := r.reconcileNetworkPolicy(ctx, desired, logger); err != nil {
			return err
		}
	}
	return nil
}

func (r *ReconcileComplianceScan) reconcileNetworkPolicy(ctx context.Context, desired *networkingv1.NetworkPolicy, logger logr.Logger) error {
	found := &networkingv1.NetworkPolicy{}
	err := r.Client.Get(ctx, types.NamespacedName{Name: desired.Name, Namespace: desired.Namespace}, found)
	if err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
		logger.Info("Creating operand NetworkPolicy", "NetworkPolicy.Name", desired.Name)
		if createErr := r.Client.Create(ctx, desired); createErr != nil && !errors.IsAlreadyExists(createErr) {
			return createErr
		}
		return nil
	}

	if reflect.DeepEqual(found.Spec, desired.Spec) {
		return nil
	}
	logger.Info("Updating operand NetworkPolicy", "NetworkPolicy.Name", desired.Name)
	found.Spec = desired.Spec
	return r.Client.Update(ctx, found)
}
