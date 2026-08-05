package common

import (
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func GetRulesFromProfile(obj *unstructured.Unstructured) ([]string, error) {
	rules, found, err := unstructured.NestedStringSlice(obj.Object, "rules")
	if err != nil {
		return nil, fmt.Errorf("Unable to get rules of %s/%s of type %s: %s", obj.GetNamespace(), obj.GetName(), "Profile", err)
	}
	if !found {
		return nil, fmt.Errorf("%s/%s of type %s: has no rules", obj.GetNamespace(), obj.GetName(), "Profile")
	}
	return rules, nil
}
