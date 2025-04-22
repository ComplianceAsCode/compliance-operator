package xccdf

import (
	"encoding/xml"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	cmpv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
)

const (
	// XMLHeader is the header for the XML doc
	XMLHeader       string = `<?xml version="1.0" encoding="UTF-8"?>`
	profileIDPrefix string = "xccdf_org.ssgproject.content_profile_"
	ruleIDPrefix    string = "xccdf_org.ssgproject.content_rule_"
	varIDPrefix     string = "xccdf_org.ssgproject.content_value_"
	// XCCDFNamespace is the XCCDF namespace of this project. Per the XCCDF
	// specification, this assiciates the content with the author
	XCCDFNamespace        string = "compliance.openshift.io"
	XCCDFURI              string = "http://checklists.nist.gov/xccdf/1.2"
	ContentFileNamePrefix string = "ssg-"
	ContentFileNameSuffix string = "-ds.xml"
)

type TailoringElement struct {
	XMLName         xml.Name `xml:"xccdf-1.2:Tailoring"`
	XMLNamespaceURI string   `xml:"xmlns:xccdf-1.2,attr"`
	ID              string   `xml:"id,attr"`
	Benchmark       BenchmarkElement
	Version         VersionElement
	Profile         ProfileElement
	// TODO(jaosorior): Add signature capabilities
	// Signature SignatureElement
}

type BenchmarkElement struct {
	XMLName xml.Name `xml:"xccdf-1.2:benchmark"`
	Href    string   `xml:"href,attr"`
}

type VersionElement struct {
	XMLName xml.Name `xml:"xccdf-1.2:version"`
	// FIXME(jaosorior): time.Time doesn't satisfy the unmarshalling
	// interface needed by the XML library in golang. I used a string
	// instead cause I was lazy.
	Time  string `xml:"time,attr"`
	Value string `xml:",chardata"`
}

type ProfileElement struct {
	XMLName     xml.Name                   `xml:"xccdf-1.2:Profile"`
	ID          string                     `xml:"id,attr"`
	Extends     string                     `xml:"extends,attr,omitempty"`
	Title       *TitleOrDescriptionElement `xml:"xccdf-1.2:title"`
	Description *TitleOrDescriptionElement `xml:"xccdf-1.2:description"`
	Selections  []SelectElement
	Values      []SetValueElement
}

type TitleOrDescriptionElement struct {
	Override bool   `xml:"override,attr"`
	Value    string `xml:",chardata"`
}

type SelectElement struct {
	XMLName  xml.Name `xml:"xccdf-1.2:select"`
	IDRef    string   `xml:"idref,attr"`
	Selected bool     `xml:"selected,attr"`
}

type SetValueElement struct {
	XMLName xml.Name `xml:"xccdf-1.2:set-value"`
	IDRef   string   `xml:"idref,attr"`
	Value   string   `xml:",chardata"`
}

// GetContentFileName gets the file name for a profile bundle
func GetContentFileName(productName string) string {
	return fmt.Sprintf("%s%s%s", ContentFileNamePrefix, productName, ContentFileNameSuffix)
}

// GetXCCDFProfileID gets a profile xccdf ID from the TailoredProfile object
func GetXCCDFProfileID(tp *cmpv1alpha1.TailoredProfile) string {
	return fmt.Sprintf("xccdf_%s_profile_%s", XCCDFNamespace, tp.Name)
}

// GetNameFromXCCDFTailoredProfileID gets the name of a tailored profile
// from the TailoredProfile ID
func GetNameFromXCCDFTailoredProfileID(id string) string {
	return strings.TrimPrefix(id, fmt.Sprintf("xccdf_%s_profile_", XCCDFNamespace))
}

// GetProfileNameFromID gets a profile name from the xccdf ID
func GetProfileNameFromID(id string) string {
	trimedName := strings.TrimPrefix(id, profileIDPrefix)
	return strings.ToLower(strings.ReplaceAll(trimedName, "_", "-"))
}

// GetProfileUniqueIDFromBundleName returns the unique identifier of the Profile
func GetProfileUniqueIDFromBundleName(pbName, profileName string) string {
	name := fmt.Sprintf("%s-%s", pbName, profileName)
	return GenerateUniqueIDFromDNS(name)
}

// GenerateUniqueIDFromDNS generates a unique identifier from a name using the DNS namespace
func GenerateUniqueIDFromDNS(name string) string {
	// Use a DNS namespace UUID
	namespace := uuid.Must(uuid.Parse("6ba7b810-9dad-11d1-80b4-00c04fd430c8"))
	uuid := uuid.NewSHA1(namespace, []byte(name))
	return uuid.String()
}

// GetProfileUniqueID gets the unique identifier of the Profile from the platform name and the profile ID
func GetProfileUniqueID(platform string, profileID string) string {
	return GetProfileUniqueIDFromBundleName(platform, profileID)
}

// GetProfileUniqueIDFromTP gets the unique identifier for a TailoredProfileID
func GetProfileUniqueIDFromTP(tpID string) string {
	return GenerateUniqueIDFromDNS(tpID)
}

// GetRuleNameFromID gets a rule name from the xccdf ID
func GetRuleNameFromID(id string) string {
	trimedName := strings.TrimPrefix(id, ruleIDPrefix)
	return strings.ToLower(strings.ReplaceAll(trimedName, "_", "-"))
}

func GetVariableNameFromID(id string) string {
	trimedName := strings.TrimPrefix(id, varIDPrefix)
	return strings.ToLower(strings.ReplaceAll(trimedName, "_", "-"))
}

func getTailoringID(tp *cmpv1alpha1.TailoredProfile) string {
	return fmt.Sprintf("xccdf_%s_tailoring_%s", XCCDFNamespace, tp.Name)
}

func getSelectElementFromCRRule(rule *cmpv1alpha1.Rule, enable bool) SelectElement {
	return SelectElement{
		IDRef:    rule.ID,
		Selected: enable,
	}
}

func getSelections(tp *cmpv1alpha1.TailoredProfile, rules map[string]*cmpv1alpha1.Rule) []SelectElement {
	selections := []SelectElement{}
	for _, selection := range tp.Spec.EnableRules {
		rule := rules[selection.Name]
		selections = append(selections, getSelectElementFromCRRule(rule, true))
	}

	for _, selection := range tp.Spec.DisableRules {
		rule := rules[selection.Name]
		selections = append(selections, getSelectElementFromCRRule(rule, false))
	}

	for _, selection := range tp.Spec.ManualRules {
		rule := rules[selection.Name]
		selections = append(selections, getSelectElementFromCRRule(rule, true))
	}
	return selections
}

func GetManualRules(tp *cmpv1alpha1.TailoredProfile) []string {
	ruleList := []string{}
	for _, selection := range tp.Spec.ManualRules {
		ruleList = append(ruleList, selection.Name)
	}
	return ruleList
}

func IsManualRule(ruleName string, manualRules []string) bool {
	if manualRules == nil {
		return false
	}
	for _, manualRule := range manualRules {
		if strings.HasSuffix(manualRule, ruleName) {
			return true
		}
	}
	return false
}

func getValuesFromVariables(variables []*cmpv1alpha1.Variable) []SetValueElement {
	values := []SetValueElement{}

	for _, varObj := range variables {
		// Ensure the variable value is properly set
		if varObj.Value == "" {
			// If no value is set, use the default value from selections if available
			if len(varObj.Selections) > 0 {
				for _, selection := range varObj.Selections {
					if selection.Description == "default" {
						varObj.Value = selection.Value
						break
					}
				}
			}
		}

		values = append(values, SetValueElement{
			IDRef: varObj.ID,
			Value: varObj.Value,
		})
	}

	return values
}

// TailoredProfileToXML gets an XML string from a TailoredProfile and the corresponding Profile
func TailoredProfileToXML(tp *cmpv1alpha1.TailoredProfile, p *cmpv1alpha1.Profile, pb *cmpv1alpha1.ProfileBundle, rules map[string]*cmpv1alpha1.Rule, variables []*cmpv1alpha1.Variable) (string, error) {
	tailoring := TailoringElement{
		XMLNamespaceURI: XCCDFURI,
		ID:              getTailoringID(tp),
		Version: VersionElement{
			Time: time.Now().Format(time.RFC3339),
			// TODO(jaosorior): Establish a TailoredProfile versioning mechanism
			Value: "1",
		},
		Benchmark: BenchmarkElement{
			// NOTE(jaosorior): Both this operator and the compliance-operator
			// assume the content will be mounted on a "content/" directory
			Href: filepath.Join("/content", pb.Spec.ContentFile),
		},
		Profile: ProfileElement{
			ID:         GetXCCDFProfileID(tp),
			Selections: getSelections(tp, rules),
			Values:     getValuesFromVariables(variables),
		},
	}
	if p != nil {
		tailoring.Profile.Extends = p.ID
	}
	if tp.Spec.Title != "" {
		tailoring.Profile.Title = &TitleOrDescriptionElement{
			Override: true,
			Value:    tp.Spec.Title,
		}
	}
	if tp.Spec.Description != "" {
		tailoring.Profile.Description = &TitleOrDescriptionElement{
			Override: true,
			Value:    tp.Spec.Description,
		}
	}

	output, err := xml.MarshalIndent(tailoring, "", "  ")
	if err != nil {
		return "", err
	}
	return XMLHeader + "\n" + string(output), nil
}
