package bind

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sserial "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/common"
)

type BindContext struct {
	common.CommandContext

	Settings string
	Name     string
	DryRun   bool

	profilesGVR            schema.GroupVersionResource
	tailoredProfilesGVR    schema.GroupVersionResource
	scanSettingsGVR        schema.GroupVersionResource
	scanSettingBindingsGVR schema.GroupVersionResource

	objects []common.ObjectReference
}

func NewBindContext(streams genericclioptions.IOStreams) *BindContext {
	return &BindContext{
		CommandContext: common.CommandContext{
			ConfigFlags: genericclioptions.NewConfigFlags(true),
			IOStreams:   streams,
		},
		profilesGVR:            common.GVR("profiles"),
		tailoredProfilesGVR:    common.GVR("tailoredprofiles"),
		scanSettingsGVR:        common.GVR("scansettings"),
		scanSettingBindingsGVR: common.GVR("scansettingbindings"),
	}
}

// Validate ensures that all required arguments and flag values are provided
func (o *BindContext) Validate() error {
	if o.Name == "" {
		return fmt.Errorf("The name parameter is required")
	}

	if o.Settings == "" {
		return fmt.Errorf("The settings parameter is required")
	}

	objrefs, err := common.ValidateManyObjectArgs(o.Args)
	if err != nil {
		return err
	}

	// Validate types
	for _, obj := range o.objects {
		switch obj.Type {
		case common.Profile:
			continue
		case common.TailoredProfile:
			continue
		default:
			return fmt.Errorf("Invalid type. Must be Profile or TailoredProfile.")
		}
	}

	// TODO(jaosorior): Validate that objects actually exist

	o.objects = objrefs
	return nil
}

func (o *BindContext) Run() error {
	scanSettingBinding := &unstructured.Unstructured{}
	ssbRaw := scanSettingBinding.UnstructuredContent()
	scanSettingBinding.SetUnstructuredContent(ssbRaw)
	scanSettingBinding.SetName(o.Name)
	scanSettingBinding.SetGroupVersionKind(
		schema.GroupVersionKind{
			Group:   common.CmpAPIGroup,
			Version: common.CmpResourceVersion,
			Kind:    "ScanSettingBinding",
		})
	gv := schema.GroupVersion{
		Group:   common.CmpAPIGroup,
		Version: common.CmpResourceVersion,
	}

	profiles := []interface{}{}
	for _, obj := range o.objects {
		var kind string
		switch obj.Type {
		case common.Profile:
			kind = "Profile"
		case common.TailoredProfile:
			kind = "TailoredProfile"
		default:
			return fmt.Errorf("Invalid type. Must be Profile or TailoredProfile.")
		}
		prof := map[string]interface{}{
			"apiGroup": gv.String(),
			"kind":     kind,
			"name":     obj.Name,
		}
		profiles = append(profiles, prof)
	}
	if err := unstructured.SetNestedSlice(ssbRaw, profiles, "profiles"); err != nil {
		return err
	}

	settingsRef := map[string]interface{}{
		"apiGroup": gv.String(),
		"kind":     "ScanSetting",
		"name":     o.Settings,
	}
	if err := unstructured.SetNestedMap(ssbRaw, settingsRef, "settingsRef"); err != nil {
		return err
	}

	if o.DryRun {
		yamlSerializer := k8sserial.NewYAMLSerializer(k8sserial.DefaultMetaFactory, nil, nil)
		common.PersistObjectToYaml(o.Name, scanSettingBinding, o.Out, yamlSerializer)
	} else {
		fmt.Fprintf(o.Out, "Creating ScanSettingBinding %s\n", o.Name)
		_, err := o.Kuser.DynamicClient().Resource(o.scanSettingBindingsGVR).Namespace(o.Kuser.GetNamespace()).Create(
			context.TODO(), scanSettingBinding, metav1.CreateOptions{})
		if err != nil {
			return err
		}
	}
	return nil
}
