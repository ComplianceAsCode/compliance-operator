package common

import (
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// GetScanNamesFromSuite gets the scan names used in a ComplianceSuite
func GetScanNamesFromSuite(obj *unstructured.Unstructured) ([]string, error) {
	scanNames := []string{}
	scans, found, err := unstructured.NestedSlice(obj.Object, "spec", "scans")
	if err != nil {
		return nil, fmt.Errorf("Unable to get scans of '%s/%s' of type %s", obj.GetNamespace(), obj.GetName(), obj.GetKind())
	}
	if !found {
		return nil, fmt.Errorf("'%s/%s' of type %s has no scans in spec", obj.GetNamespace(), obj.GetName(), obj.GetKind())
	}
	for _, rawscan := range scans {
		scan, ok := rawscan.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("Couldn't parse scan: %v", rawscan)
		}
		name, found, err := unstructured.NestedString(scan, "name")
		if err != nil {
			return nil, fmt.Errorf("Unable to get scan name of '%s/%s' of type %s", obj.GetNamespace(), obj.GetName(), obj.GetKind())
		}
		if !found {
			return nil, fmt.Errorf("'%s/%s' of type %s has no scan name in spec", obj.GetNamespace(), obj.GetName(), obj.GetKind())
		}

		scanNames = append(scanNames, name)
	}
	return scanNames, nil
}
