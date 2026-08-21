package deployment_e2e

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
)

// Names mirror the constants in pkg/controller/compliancescan/networkpolicy.go.
// The e2e treats the operator as a black box, so they are duplicated here.
const (
	npDefaultDeny         = "compliance-operator-operands-default-deny"
	npAllowEgress         = "compliance-operator-operands-allow-egress"
	npResultServerIngress = "compliance-operator-resultserver-allow-ingress"
)

// TestOperandNetworkPoliciesAreReconciled verifies that running a scan causes the
// operator to reconcile the operand NetworkPolicies, and that operands still
// function with the policies in place. A node scan is used deliberately: its
// host-networked scanner pods must reach the result server on 8443 through the
// ingress policy, so the scan reaching Done exercises the host-network ingress
// path end to end.
func TestOperandNetworkPoliciesAreReconciled(t *testing.T) {
	f := framework.Global

	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile:      "xccdf_org.ssgproject.content_profile_moderate",
			Content:      framework.RhcosContentFile,
			ContentImage: contentImagePath,
			// A single rule keeps the scan fast; we only care that operands run.
			Rule: "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				Debug: true,
			},
		},
	}
	if err := f.Client.Create(context.TODO(), testScan, nil); err != nil {
		t.Fatalf("failed to create scan %s: %s", scanName, err)
	}
	defer f.Client.Delete(context.TODO(), testScan)

	// Reaching Done means the host-networked scanner delivered its results to the
	// result server through the ingress policy: operands function with policies in
	// place.
	if err := f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone); err != nil {
		t.Fatalf("scan %s did not complete with NetworkPolicies in place: %s", scanName, err)
	}

	// All three operand NetworkPolicies must exist.
	for _, name := range []string{npDefaultDeny, npAllowEgress, npResultServerIngress} {
		np, err := f.KubeClient.NetworkingV1().NetworkPolicies(f.OperatorNamespace).Get(
			context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("expected NetworkPolicy %q to exist: %s", name, err)
		}
		if len(np.Spec.PolicyTypes) == 0 {
			t.Errorf("NetworkPolicy %q has no policy types", name)
		}
	}

	// default-deny must select operand pods and carry no allow rules.
	dd, err := f.KubeClient.NetworkingV1().NetworkPolicies(f.OperatorNamespace).Get(
		context.TODO(), npDefaultDeny, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := dd.Spec.PodSelector.MatchLabels[compv1alpha1.NetworkPolicyOperandLabel]; !ok {
		t.Errorf("default-deny does not select operand pods: %v", dd.Spec.PodSelector.MatchLabels)
	}
	if len(dd.Spec.Ingress) != 0 || len(dd.Spec.Egress) != 0 {
		t.Errorf("default-deny must have no allow rules, got ingress=%d egress=%d",
			len(dd.Spec.Ingress), len(dd.Spec.Egress))
	}

	// result-server ingress must open the result server port.
	rs, err := f.KubeClient.NetworkingV1().NetworkPolicies(f.OperatorNamespace).Get(
		context.TODO(), npResultServerIngress, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Spec.Ingress) != 1 || len(rs.Spec.Ingress[0].Ports) != 1 {
		t.Fatalf("unexpected result-server ingress rule shape: %+v", rs.Spec.Ingress)
	}
	if p := rs.Spec.Ingress[0].Ports[0].Port; p == nil || p.IntVal != 8443 {
		t.Errorf("result-server ingress should open port 8443, got %v", p)
	}
}
