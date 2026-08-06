package controls

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/ComplianceAsCode/compliance-operator/pkg/oc-compliance/common"
)

const controlAnnotationPrefix = "control.compliance.openshift.io/"

type BenchMarkCtrlsMapping map[string]CtrlRulesMapping

type CtrlRulesMapping map[string]RulesList

type RulesList []string

type ProfileHelper struct {
	kuser   common.KubeClientUser
	gvk     schema.GroupVersionResource
	rulegvk schema.GroupVersionResource
	kind    string
	name    string
	genericclioptions.IOStreams
	benchmark string
}

func NewProfileHelper(kuser common.KubeClientUser, name string, streams genericclioptions.IOStreams, b string) common.ObjectHelper {
	return &ProfileHelper{
		kuser: kuser,
		name:  name,
		kind:  "Profile",
		gvk: schema.GroupVersionResource{
			Group:    common.CmpAPIGroup,
			Version:  common.CmpResourceVersion,
			Resource: "profiles",
		},
		rulegvk: schema.GroupVersionResource{
			Group:    common.CmpAPIGroup,
			Version:  common.CmpResourceVersion,
			Resource: "rules",
		},
		IOStreams:  streams,
		benchmark: b,
	}
}

func (h *ProfileHelper) Handle() error {
	results := BenchMarkCtrlsMapping{}

	p, err := h.kuser.DynamicClient().Resource(h.gvk).Namespace(h.kuser.GetNamespace()).Get(context.TODO(), h.name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	rules, err := common.GetRulesFromProfile(p)
	if err != nil {
		return err
	}
	for _, rulename := range rules {
		r, err := h.kuser.DynamicClient().Resource(h.rulegvk).Namespace(h.kuser.GetNamespace()).Get(context.TODO(), rulename, metav1.GetOptions{})
		if err != nil {
			return err
		}
		annotations := r.GetAnnotations()
		if annotations == nil {
			continue
		}

		for key, value := range annotations {
			if strings.HasPrefix(key, controlAnnotationPrefix) {
				ctrl := value
				benchmark := strings.Split(key, "/")[1]
				results = h.insertControlEntries(results, benchmark, ctrl, rulename)
			}
		}
	}

	h.render(results)
	return nil
}

func (h *ProfileHelper) render(res BenchMarkCtrlsMapping) {
	table := tablewriter.NewTable(h.Out,
		tablewriter.WithRowMergeMode(tw.MergeVertical),
	)
	table.Header([]string{"Framework", "Controls", "Rules"})

	for benchmark, bmap := range res {
		if !h.benchmarkMatches(benchmark) {
			continue
		}
		controls := make([]string, 0, len(bmap))
		for k := range bmap {
			controls = append(controls, k)
		}
		sort.Strings(controls)
		for _, control := range controls {
			rules := bmap[control]
			sort.Strings(rules)
			for _, rule := range rules {
				table.Append([]string{benchmark, control, rule})
			}
		}
	}
	table.Render()
}

func (h *ProfileHelper) insertControlEntries(res BenchMarkCtrlsMapping, benchmark, rawcontrols, rulename string) BenchMarkCtrlsMapping {
	if !h.benchmarkMatches(benchmark) {
		return res
	}

	benchMap, bfound := res[benchmark]
	// init benchmark
	if !bfound {
		res[benchmark] = make(CtrlRulesMapping)
		benchMap = res[benchmark]
	}
	controls := strings.Split(rawcontrols, ";")
	for _, incomingctrl := range controls {
		if incomingctrl == "" {
			fmt.Printf("WARNING: empty control in %s", rawcontrols)
			continue
		}
		rules, ctrlfound := benchMap[incomingctrl]
		if !ctrlfound {
			benchMap[incomingctrl] = make(RulesList, 0)
			rules = benchMap[incomingctrl]
		}
		benchMap[incomingctrl] = append(rules, rulename)
	}
	return res
}

func (h *ProfileHelper) benchmarkMatches(benchmark string) bool {
	return h.benchmark == AllBenchmarks || h.benchmark == benchmark
}
