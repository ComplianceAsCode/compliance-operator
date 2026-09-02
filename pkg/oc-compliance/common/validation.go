package common

import (
	"fmt"
	"strings"
)

type ComplianceType int

const (
	ComplianceScan ComplianceType = iota
	ComplianceSuite
	ComplianceRemediation
	ScanSettingBinding
	Profile
	TailoredProfile
	Rule
	ComplianceCheckResult
	TypeUnknown
)

type ObjectReference struct {
	Type ComplianceType
	Name string
}

func ValidateObjectArgs(args []string) (objref ObjectReference, err error) {

	if len(args) < 1 {
		err = fmt.Errorf("You need to specify at least one object")
		return
	}

	if len(args) > 2 {
		err = fmt.Errorf("unkown argument(s): %s", args[2:])
		return
	}

	var rawobjtype string
	if len(args) == 1 {
		objparts := strings.Split(args[0], "/")
		if len(objparts) == 1 {
			return ObjectReference{TypeUnknown, ""}, fmt.Errorf("Missing object type")
		}

		if len(objparts) > 2 {
			return ObjectReference{TypeUnknown, ""}, fmt.Errorf("Malformed reference to object: %s", args[0])
		}

		rawobjtype = objparts[0]
		objref.Name = objparts[1]
	} else {
		rawobjtype = args[0]
		objref.Name = args[1]
	}

	objref.Type, err = GetValidObjType(rawobjtype)
	return
}

func ValidateManyObjectArgs(args []string) ([]ObjectReference, error) {
	out := []ObjectReference{}
	if len(args) < 1 {
		return nil, fmt.Errorf("You need to specify at least one object")
	}

	for i := range args {
		ref, err := ValidateObjectArgs(args[i : i+1])
		if err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return out, nil
}

func GetValidObjType(rawtype string) (ComplianceType, error) {
	switch rawtype {
	case "ScanSettingBindings", "ScanSettingBinding", "scansettingbindings", "scansettingbinding":
		return ScanSettingBinding, nil
	case "ComplianceSuites", "ComplianceSuite", "compliancesuites", "compliancesuite":
		return ComplianceSuite, nil
	case "ComplianceScans", "ComplianceScan", "compliancescans", "compliancescan":
		return ComplianceScan, nil
	case "ComplianceRemediations", "ComplianceRemediation", "complianceremediations", "complianceremediation":
		return ComplianceRemediation, nil
	case "Profiles", "Profile", "profiles", "profile":
		return Profile, nil
	case "TailoredProfiles", "TailoredProfile", "tailoredprofiles", "tailoredprofile":
		return TailoredProfile, nil
	case "Rules", "Rule", "rules", "rule":
		return Rule, nil
	case "ComplianceCheckResults", "ComplianceCheckResult", "compliancecheckresults", "compliancecheckresult":
		return ComplianceCheckResult, nil
	default:
		return TypeUnknown, fmt.Errorf("Unknown object type: %s", rawtype)
	}
}
