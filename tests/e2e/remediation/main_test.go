package remediation_e2e

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

var brokenContentImagePath string
var contentImagePath string

func TestMain(m *testing.M) {
	f := framework.NewFramework()
	err := f.SetUp()
	if err != nil {
		log.Fatal(err)
	}

	contentImagePath = os.Getenv("CONTENT_IMAGE")
	if contentImagePath == "" {
		fmt.Println("Please set the 'CONTENT_IMAGE' environment variable")
		os.Exit(1)
	}

	brokenContentImagePath = os.Getenv("BROKEN_CONTENT_IMAGE")

	if brokenContentImagePath == "" {
		fmt.Println("Please set the 'BROKEN_CONTENT_IMAGE' environment variable")
		os.Exit(1)
	}

	exitCode := m.Run()
	if exitCode == 0 || (exitCode > 0 && f.CleanUpOnError()) {
		if err = f.TearDown(); err != nil {
			log.Fatal(err)
		}
	}
	os.Exit(exitCode)
}

func TestApplyGenericRemediation(t *testing.T) {
	t.Parallel()
	f := framework.Global
	remName := "test-apply-generic-remediation"
	unstruct := &unstructured.Unstructured{}
	unstruct.SetUnstructuredContent(map[string]interface{}{
		"kind":       "ConfigMap",
		"apiVersion": "v1",
		"metadata": map[string]interface{}{
			"name":      "generic-rem-cm",
			"namespace": f.OperatorNamespace,
		},
		"data": map[string]interface{}{
			"key": "value",
		},
	})

	genericRem := &compv1alpha1.ComplianceRemediation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      remName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceRemediationSpec{
			ComplianceRemediationSpecMeta: compv1alpha1.ComplianceRemediationSpecMeta{
				Apply: true,
			},
			Current: compv1alpha1.ComplianceRemediationPayload{
				Object: unstruct,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), genericRem, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), genericRem)
	err = f.WaitForRemediationState(remName, f.OperatorNamespace, compv1alpha1.RemediationApplied)
	if err != nil {
		t.Fatal(err)
	}

	cm := &corev1.ConfigMap{}
	cmName := "generic-rem-cm"
	err = f.WaitForObjectToExist(cmName, f.OperatorNamespace, cm)
	if err != nil {
		t.Fatal(err)
	}
	val, ok := cm.Data["key"]
	if !ok || val != "value" {
		t.Fatalf("ComplianceRemediation '%s' generated a malformed ConfigMap", remName)
	}

	// verify object is marked as created by the operator
	if !compv1alpha1.RemediationWasCreatedByOperator(cm) {
		t.Fatalf("ComplianceRemediation '%s' is missing controller annotation '%s'",
			remName, compv1alpha1.RemediationCreatedByOperatorAnnotation)
	}
}

func TestPatchGenericRemediation(t *testing.T) {
	t.Parallel()
	f := framework.Global
	remName := framework.GetObjNameFromTest(t)
	cmName := remName
	cmKey := types.NamespacedName{
		Name:      cmName,
		Namespace: f.OperatorNamespace,
	}
	existingCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmKey.Name,
			Namespace: cmKey.Namespace,
		},
		Data: map[string]string{
			"existingKey": "existingData",
		},
	}

	if err := f.Client.Create(context.TODO(), existingCM, nil); err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), existingCM)

	cm := &corev1.ConfigMap{}
	err := f.WaitForObjectToExist(cmKey.Name, f.OperatorNamespace, cm)
	if err != nil {
		t.Fatal(err)
	}

	unstruct := &unstructured.Unstructured{}
	unstruct.SetUnstructuredContent(map[string]interface{}{
		"kind":       "ConfigMap",
		"apiVersion": "v1",
		"metadata": map[string]interface{}{
			"name":      cmKey.Name,
			"namespace": cmKey.Namespace,
		},
		"data": map[string]interface{}{
			"newKey": "newData",
		},
	})

	genericRem := &compv1alpha1.ComplianceRemediation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      remName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceRemediationSpec{
			ComplianceRemediationSpecMeta: compv1alpha1.ComplianceRemediationSpecMeta{
				Apply: true,
			},
			Current: compv1alpha1.ComplianceRemediationPayload{
				Object: unstruct,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err = f.Client.Create(context.TODO(), genericRem, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), genericRem)

	err = f.WaitForRemediationState(remName, f.OperatorNamespace, compv1alpha1.RemediationApplied)
	if err != nil {
		t.Fatal(err)
	}

	err = f.WaitForObjectToUpdate(cmKey.Name, f.OperatorNamespace, cm)
	if err != nil {
		t.Fatal(err)
	}

	// Old data should still be there
	val, ok := cm.Data["existingKey"]
	if !ok || val != "existingData" {
		t.Fatalf("ComplianceRemediation '%s' generated a malformed ConfigMap", remName)
	}

	// new data should be there too
	val, ok = cm.Data["newKey"]
	if !ok || val != "newData" {
		t.Fatalf("ComplianceRemediation '%s' generated a malformed ConfigMap", remName)
	}
}

func TestGenericRemediationFailsWithUnknownType(t *testing.T) {
	t.Parallel()
	f := framework.Global
	remName := "test-generic-remediation-fails-unknown"
	genericRem := &compv1alpha1.ComplianceRemediation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      remName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceRemediationSpec{
			ComplianceRemediationSpecMeta: compv1alpha1.ComplianceRemediationSpecMeta{
				Apply: true,
			},
			Current: compv1alpha1.ComplianceRemediationPayload{
				Object: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"kind":       "OopsyDoodle",
						"apiVersion": "foo.bar/v1",
						"metadata": map[string]interface{}{
							"name":      "unknown-remediation",
							"namespace": f.OperatorNamespace,
						},
						"data": map[string]interface{}{
							"key": "value",
						},
					},
				},
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), genericRem, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), genericRem)
	err = f.WaitForRemediationState(remName, f.OperatorNamespace, compv1alpha1.RemediationError)
	if err != nil {
		t.Fatal(err)
	}
}

