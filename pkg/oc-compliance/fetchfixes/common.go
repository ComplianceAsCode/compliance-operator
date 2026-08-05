package fetchfixes

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sserial "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/common"
)

const roleKey = "machineconfiguration.openshift.io/role"

type FixPersister struct {
	outputPath string
	mcRoles    []string
	genericclioptions.IOStreams
}

func (fp *FixPersister) handleObjectPersistence(ys *k8sserial.Serializer, fileNameBase string, fix *unstructured.Unstructured) error {
	if isEnforcementRemediation(fix) {
		return nil
	}
	if fix.GetKind() == "MachineConfig" {
		for _, role := range fp.mcRoles {
			handleMCMetadata(fix, fileNameBase, role)
			fileWithRole := fmt.Sprintf("%s-%s", role, fileNameBase)
			err := fp.persistFix(ys, fileWithRole, fix)
			if err != nil {
				return err
			}
		}
		return nil
	}

	err := fp.persistFix(ys, fileNameBase, fix)
	if err != nil {
		return err
	}
	return nil
}

func (fp *FixPersister) persistFix(ys *k8sserial.Serializer, fileNameBase string, fix *unstructured.Unstructured) error {
	path, err := common.PersistObjectToYamlFile(fileNameBase, fix, fp.outputPath, ys)
	if err != nil {
		return err
	}

	fmt.Fprintf(fp.Out, "Persisted rule fix to %s\n", path)
	return nil
}

func handleMCMetadata(obj *unstructured.Unstructured, baseName, role string) {
	obj.SetName(fmt.Sprintf("75-%s-%s", role, baseName))
	if len(obj.GetLabels()) == 0 {
		obj.SetLabels(make(map[string]string))
	}

	labels := obj.GetLabels()
	labels[roleKey] = role
	obj.SetLabels(labels)
}

func isEnforcementRemediation(obj *unstructured.Unstructured) bool {
	if len(obj.GetAnnotations()) == 0 {
		return false
	}
	anns := obj.GetAnnotations()
	rtype, ok := anns["complianceascode.io/remediation-type"]
	if !ok {
		return false
	}
	return strings.EqualFold(rtype, "Enforcement")
}
