package compliancesuite

import (
	"context"

	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/common"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
)

// GetRerunnerName gets the name of the rerunner workload based on the suite name
func GetRerunnerName(suiteName string) string {
	// Operator SDK doesn't allow CronJob with names longer than 52
	// characters. Trim everything but the first 42 characters so we have
	// enough room for the "-rerunner" string.
	if len(suiteName) >= 42 {
		suiteName = suiteName[0:42]
	}
	return suiteName + "-rerunner"
}

func (r *ReconcileComplianceSuite) CreateOrUpdateRerunner(
	suite *compv1alpha1.ComplianceSuite,
	key types.NamespacedName,
	logger logr.Logger,
) error {
	c := batchv1.CronJob{}
	err := r.Client.Get(context.TODO(), key, &c)

	if err != nil && errors.IsNotFound(err) {
		return r.createCronJob(suite, &c, logger)
	} else if err != nil {
		return err
	}
	return r.updateCronJob(suite, &c, logger)
}

func (r *ReconcileComplianceSuite) getCronJob(key types.NamespacedName) (batchv1.CronJob, error) {
	c := batchv1.CronJob{}
	err := r.Client.Get(context.TODO(), key, &c)
	if err != nil {
		return c, err
	}
	return c, nil
}

func (r *ReconcileComplianceSuite) createCronJob(suite *compv1alpha1.ComplianceSuite, c *batchv1.CronJob, logger logr.Logger) error {
	logger.Info("Creating rerunner", "CronJob.Name", c.GetName())
	priorityClassName, err := r.getPriorityClassName(suite)
	if err != nil {
		logger.Error(err, "Cannot get priority class name, scan will not be run with set priority class")
	}
	s := r.generateRerunnerSpec(suite, priorityClassName)
	return r.Client.Create(context.TODO(), s)
}

func (r *ReconcileComplianceSuite) updateCronJob(suite *compv1alpha1.ComplianceSuite, c *batchv1.CronJob, logger logr.Logger) error {
	var isSameSchedule = c.Spec.Schedule == suite.Spec.Schedule
	var isSuspend = c.Spec.Suspend == &suite.Spec.Suspend
	var isSameImage = c.Spec.JobTemplate.Spec.Template.Spec.Containers[0].Image == utils.GetComponentImage(utils.OPERATOR)
	if isSameSchedule && isSuspend && isSameImage {
		logger.Info("Suite rerunner configuration is up-to-date, no update necessary", "CronJob.Name", c.GetName())
		return nil
	}
	logger.Info("Updating rerunner configuration", "CronJob.Name", c.GetName())
	co := c.DeepCopy()
	co.Spec.Schedule = suite.Spec.Schedule
	co.Spec.Suspend = &suite.Spec.Suspend
	co.Spec.JobTemplate.Spec.Template.Spec.Containers[0].Image = utils.GetComponentImage(utils.OPERATOR)
	return r.Client.Update(context.TODO(), co)
}

func reRunnerNamespacedName(suiteName string) types.NamespacedName {
	return types.NamespacedName{
		Name:      GetRerunnerName(suiteName),
		Namespace: common.GetComplianceOperatorNamespace(),
	}
}

func reRunnerObjectMeta(suiteName string) *metav1.ObjectMeta {
	nsName := reRunnerNamespacedName(suiteName)

	return &metav1.ObjectMeta{
		Name:      nsName.Name,
		Namespace: nsName.Namespace,
	}
}

func (r *ReconcileComplianceSuite) generateRerunnerSpec(
	suite *compv1alpha1.ComplianceSuite,
	priorityClassName string,
) *batchv1.CronJob {
	return &batchv1.CronJob{
		ObjectMeta: *reRunnerObjectMeta(suite.Name),
		Spec: batchv1.CronJobSpec{
			Schedule: suite.Spec.Schedule,
			JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{
					Template: *r.getRerunnerPodTemplate(suite, priorityClassName),
				},
			},
		},
	}
}

func (r *ReconcileComplianceSuite) getRerunnerPodTemplate(
	suite *compv1alpha1.ComplianceSuite,
	priorityClassName string,
) *corev1.PodTemplateSpec {
	falseP := false
	trueP := true

	// We need to support both v1 and beta1 CronJobs, so we need to use the
	// same pod template for both. We can't use the same CronJob object
	// because the API is different.
	return &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				compv1alpha1.SuiteLabel:       suite.Name,
				compv1alpha1.SuiteScriptLabel: "",
				"workload":                    "suitererunner",
			},
			Annotations: map[string]string{
				"workload.openshift.io/management": `{"effect": "PreferredDuringScheduling"}`,
			},
		},
		Spec: corev1.PodSpec{
			NodeSelector:       r.schedulingInfo.Selector,
			Tolerations:        r.schedulingInfo.Tolerations,
			ServiceAccountName: rerunnerServiceAccount,
			RestartPolicy:      corev1.RestartPolicyOnFailure,
			PriorityClassName:  priorityClassName,
			Containers: []corev1.Container{
				{
					Name:            "rerunner",
					Image:           utils.GetComponentImage(utils.OPERATOR),
					ImagePullPolicy: corev1.PullIfNotPresent,
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: &falseP,
						ReadOnlyRootFilesystem:   &trueP,
					},
					Command: []string{
						"compliance-operator", "suitererunner",
						"--name", suite.GetName(),
						"--namespace", suite.GetNamespace(),
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("20Mi"),
							corev1.ResourceCPU:    resource.MustParse("10m"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("100Mi"),
							corev1.ResourceCPU:    resource.MustParse("50m"),
						},
					},
				},
			},
		},
	}
}
