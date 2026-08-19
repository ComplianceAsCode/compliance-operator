package compliancescan

import (
	"context"
	"reflect"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/common"
)

func TestDefaultDenyNetworkPolicy(t *testing.T) {
	np := defaultDenyNetworkPolicy("openshift-compliance")

	if np.Name != networkPolicyDefaultDeny {
		t.Errorf("unexpected name: got %q, want %q", np.Name, networkPolicyDefaultDeny)
	}
	if v, ok := np.Spec.PodSelector.MatchLabels[compv1alpha1.NetworkPolicyOperandLabel]; !ok || v != "" {
		t.Errorf("expected operand marker in pod selector, got matchLabels %v", np.Spec.PodSelector.MatchLabels)
	}
	// Both policy types with no rules => deny ingress and egress.
	if len(np.Spec.PolicyTypes) != 2 {
		t.Errorf("expected Ingress+Egress policy types, got %v", np.Spec.PolicyTypes)
	}
	if len(np.Spec.Ingress) != 0 || len(np.Spec.Egress) != 0 {
		t.Errorf("default-deny must have no ingress/egress rules, got ingress=%d egress=%d",
			len(np.Spec.Ingress), len(np.Spec.Egress))
	}
}

func TestAllowEgressNetworkPolicy(t *testing.T) {
	np := allowEgressNetworkPolicy("openshift-compliance")

	if np.Name != networkPolicyAllowEgress {
		t.Errorf("unexpected name: got %q, want %q", np.Name, networkPolicyAllowEgress)
	}
	if len(np.Spec.PolicyTypes) != 1 || np.Spec.PolicyTypes[0] != networkingv1.PolicyTypeEgress {
		t.Errorf("expected only Egress policy type, got %v", np.Spec.PolicyTypes)
	}
	// A single empty egress rule allows all egress.
	if len(np.Spec.Egress) != 1 {
		t.Fatalf("expected exactly one (allow-all) egress rule, got %d", len(np.Spec.Egress))
	}
	if len(np.Spec.Egress[0].To) != 0 || len(np.Spec.Egress[0].Ports) != 0 {
		t.Errorf("allow-all egress rule must have no peers/ports, got to=%d ports=%d",
			len(np.Spec.Egress[0].To), len(np.Spec.Egress[0].Ports))
	}
}

func TestResultServerIngressNetworkPolicy(t *testing.T) {
	np := resultServerIngressNetworkPolicy("openshift-compliance")

	if np.Name != networkPolicyResultServerIngress {
		t.Errorf("unexpected name: got %q, want %q", np.Name, networkPolicyResultServerIngress)
	}
	if got := np.Spec.PodSelector.MatchLabels[WorkloadLabel]; got != WorkloadResultServer {
		t.Errorf("expected pod selector on result server, got %v", np.Spec.PodSelector.MatchLabels)
	}
	if len(np.Spec.PolicyTypes) != 1 || np.Spec.PolicyTypes[0] != networkingv1.PolicyTypeIngress {
		t.Errorf("expected only Ingress policy type, got %v", np.Spec.PolicyTypes)
	}
	if len(np.Spec.Ingress) != 1 {
		t.Fatalf("expected one ingress rule, got %d", len(np.Spec.Ingress))
	}
	rule := np.Spec.Ingress[0]

	// Port: TCP on the result server port.
	if len(rule.Ports) != 1 {
		t.Fatalf("expected one ingress port, got %d", len(rule.Ports))
	}
	if rule.Ports[0].Protocol == nil || *rule.Ports[0].Protocol != corev1.ProtocolTCP {
		t.Errorf("expected TCP ingress port, got %v", rule.Ports[0].Protocol)
	}
	if rule.Ports[0].Port == nil || rule.Ports[0].Port.IntVal != ResultServerPort {
		t.Errorf("expected ingress port %d, got %v", ResultServerPort, rule.Ports[0].Port)
	}

	// Two peers: pod-network scanners and host-network node scanners.
	if len(rule.From) != 2 {
		t.Fatalf("expected two ingress peers (scanner podSelector + host-network ns), got %d", len(rule.From))
	}
	var haveScannerPod, haveHostNetworkNS bool
	for _, peer := range rule.From {
		if peer.PodSelector != nil && peer.PodSelector.MatchLabels[WorkloadLabel] == WorkloadScanner {
			haveScannerPod = true
		}
		if peer.NamespaceSelector != nil {
			if _, ok := peer.NamespaceSelector.MatchLabels[hostNetworkNamespaceLabel]; ok {
				haveHostNetworkNS = true
			}
		}
	}
	if !haveScannerPod {
		t.Error("missing scanner podSelector ingress peer")
	}
	if !haveHostNetworkNS {
		t.Error("missing host-network namespaceSelector ingress peer")
	}
}

// newNetworkPolicyTestReconciler returns a reconciler backed by an in-memory
// fake client (no cluster / envtest needed).
func newNetworkPolicyTestReconciler(objs ...*networkingv1.NetworkPolicy) *ReconcileComplianceScan {
	builder := fake.NewClientBuilder().WithScheme(scheme.Scheme)
	for _, o := range objs {
		builder = builder.WithObjects(o)
	}
	return &ReconcileComplianceScan{Client: builder.Build()}
}

func listNetworkPolicies(t *testing.T, r *ReconcileComplianceScan) *networkingv1.NetworkPolicyList {
	t.Helper()
	list := &networkingv1.NetworkPolicyList{}
	if err := r.Client.List(context.TODO(), list); err != nil {
		t.Fatalf("listing network policies: %v", err)
	}
	return list
}

func TestReconcileNetworkPoliciesCreatesAll(t *testing.T) {
	r := newNetworkPolicyTestReconciler()

	if err := r.reconcileNetworkPolicies(context.TODO(), logr.Discard()); err != nil {
		t.Fatalf("reconcileNetworkPolicies: %v", err)
	}

	ns := common.GetComplianceOperatorNamespace()
	want := operandNetworkPolicies(ns)
	list := listNetworkPolicies(t, r)
	if len(list.Items) != len(want) {
		t.Fatalf("expected %d network policies, got %d", len(want), len(list.Items))
	}
	for _, desired := range want {
		found := &networkingv1.NetworkPolicy{}
		key := types.NamespacedName{Name: desired.Name, Namespace: ns}
		if err := r.Client.Get(context.TODO(), key, found); err != nil {
			t.Errorf("policy %q not created: %v", desired.Name, err)
		}
	}
}

func TestReconcileNetworkPoliciesIdempotent(t *testing.T) {
	r := newNetworkPolicyTestReconciler()

	if err := r.reconcileNetworkPolicies(context.TODO(), logr.Discard()); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	first := listNetworkPolicies(t, r)

	// A second reconcile must not error and must not create duplicates.
	if err := r.reconcileNetworkPolicies(context.TODO(), logr.Discard()); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	second := listNetworkPolicies(t, r)

	if len(second.Items) != len(first.Items) {
		t.Fatalf("reconcile not idempotent: policy count changed from %d to %d",
			len(first.Items), len(second.Items))
	}
}

func assertHasNetworkPolicyMarker(t *testing.T, operand string, labels map[string]string) {
	t.Helper()
	if v, ok := labels[compv1alpha1.NetworkPolicyOperandLabel]; !ok || v != "" {
		t.Errorf("%s pod template missing NetworkPolicy marker label (labels=%v)", operand, labels)
	}
}

// TestOperandPodTemplatesCarryNetworkPolicyMarker verifies every operand pod
// template built by this package carries the marker so the operand policies
// select it, and that the marker does not leak into the immutable result-server
// Deployment selector.
func TestOperandPodTemplatesCarryNetworkPolicyMarker(t *testing.T) {
	logger := logr.Discard()
	r := &ReconcileComplianceScan{}
	scan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-scan",
			Namespace: common.GetComplianceOperatorNamespace(),
		},
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1"}}

	rs := resultServer(scan, getResultServerLabels(scan), 0, 0, logger)
	assertHasNetworkPolicyMarker(t, "result server", rs.Spec.Template.ObjectMeta.Labels)
	if _, ok := rs.Spec.Selector.MatchLabels[compv1alpha1.NetworkPolicyOperandLabel]; ok {
		t.Error("result server Deployment selector must not carry the NetworkPolicy marker")
	}

	assertHasNetworkPolicyMarker(t, "node scanner", newScanPodForNode(scan, node, logger).Labels)
	assertHasNetworkPolicyMarker(t, "platform scanner", r.newPlatformScanPod(scan, logger).Labels)
	assertHasNetworkPolicyMarker(t, "aggregator", r.newAggregatorPod(scan, logger).Labels)
}

func TestReconcileNetworkPolicyCorrectsDrift(t *testing.T) {
	ns := common.GetComplianceOperatorNamespace()

	// Seed a default-deny policy with a drifted spec (wrong pod selector).
	drifted := defaultDenyNetworkPolicy(ns)
	drifted.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"drifted": "true"}}
	r := newNetworkPolicyTestReconciler(drifted)

	if err := r.reconcileNetworkPolicies(context.TODO(), logr.Discard()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	found := &networkingv1.NetworkPolicy{}
	key := types.NamespacedName{Name: networkPolicyDefaultDeny, Namespace: ns}
	if err := r.Client.Get(context.TODO(), key, found); err != nil {
		t.Fatalf("get after reconcile: %v", err)
	}
	want := defaultDenyNetworkPolicy(ns)
	if !reflect.DeepEqual(found.Spec, want.Spec) {
		t.Errorf("drift not corrected:\n got  %+v\n want %+v", found.Spec, want.Spec)
	}
}
