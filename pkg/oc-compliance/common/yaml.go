package common

import (
	"fmt"
	"io"
	"os"
	"path"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	k8sserial "k8s.io/apimachinery/pkg/runtime/serializer/json"
)

// PersistObjectToYamlFile persists the given object to a yaml file in the given path
func PersistObjectToYamlFile(fileNameBase string, obj *unstructured.Unstructured, outputDir string, serializer *k8sserial.Serializer) (string, error) {
	path := path.Join(outputDir, fileNameBase+".yaml")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", err
	}

	defer f.Close()

	if err := PersistObjectToYaml(fileNameBase, obj, f, serializer); err != nil {
		return "", nil
	}

	if err = f.Sync(); err != nil {
		return "", err
	}
	return path, nil
}

func PersistObjectToYaml(name string, obj *unstructured.Unstructured, w io.Writer, serializer *k8sserial.Serializer) error {
	writer := json.YAMLFramer.NewFrameWriter(w)

	// Needed for MachineConfigs
	if obj.GetName() == "" {
		obj.SetName(name)
	}

	if err := serializer.Encode(obj, writer); err != nil {
		return fmt.Errorf("Couldn't serialize YAML for '%s': %s", name, err)
	}

	return nil
}
