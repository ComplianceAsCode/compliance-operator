package compliancesuite

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
)

// TestRerunnerPodTemplateCarriesNetworkPolicyMarker verifies the rerunner
// CronJob pod template carries the operand NetworkPolicy marker so the operand
// policies select it.
func TestRerunnerPodTemplateCarriesNetworkPolicyMarker(t *testing.T) {
	r := &ReconcileComplianceSuite{}
	suite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-suite",
			Namespace: "openshift-compliance",
		},
	}

	tmpl := r.getRerunnerPodTemplate(suite, "")
	if v, ok := tmpl.ObjectMeta.Labels[compv1alpha1.NetworkPolicyOperandLabel]; !ok || v != "" {
		t.Errorf("rerunner pod template missing NetworkPolicy marker (labels=%v)", tmpl.ObjectMeta.Labels)
	}
}
