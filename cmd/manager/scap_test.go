package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/common"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
	"github.com/antchfx/xmlquery"
	igntypes "github.com/coreos/ignition/v2/config/v3_2/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Testing SCAP parsing and storage", func() {
	// Turn to `true` if debugging
	debugLog = true

	Context("Parsing SCAP Content", func() {
		var dataStreamFile *os.File
		var contentDS *xmlquery.Node

		BeforeEach(func() {
			var err error
			dataStreamFile, err = os.Open("../../tests/data/ssg-ocp4-ds-new.xml")
			Expect(err).To(BeNil())
		})
		AfterEach(func() {
			dataStreamFile.Close()
		})

		It("Gets the appropriate resource URIs", func() {
			By("parsing content without errors")
			var err error
			contentDS, err = parseContent(dataStreamFile)
			Expect(err).To(BeNil())

			By("parsing content for warnings")
			expected := []utils.ResourcePath{
				{
					ObjPath:  "/apis/config.openshift.io/v1/oauths/cluster",
					DumpPath: "/apis/config.openshift.io/v1/oauths/cluster",
				},
				{
					ObjPath:  "/api/v1/namespaces/openshift-kube-apiserver/configmaps/config",
					DumpPath: "/api/v1/namespaces/openshift-kube-apiserver/configmaps/config",
				},
			}
			got, _ := getResourcePaths(contentDS, contentDS, "xccdf_org.ssgproject.content_profile_platform-moderate", nil)
			Expect(got).To(Equal(expected))
		})
	})

	Context("Parsing SCAP Content with runtime customization for OCP API resource", func() {
		var dataStreamFile *os.File
		var contentDS *xmlquery.Node

		It("Gets the appropriate resource URIs", func() {
			var err error
			dataStreamFile, err = os.Open("../../tests/data/ssg-ocp4-ds-new-warning-variable.xml")
			Expect(err).To(BeNil())

			By("parsing content without errors")
			contentDS, err = parseContent(dataStreamFile)
			Expect(err).To(BeNil())

			By("parsing content for warnings")
			expected := []utils.ResourcePath{
				{
					ObjPath:  "/apis/config.openshift.io/v1/oauths/cluster",
					DumpPath: "/apis/config.openshift.io/v1/oauths/cluster",
				},
				{
					ObjPath:  "/api/v1/namespaces/master-mycluster1/configmaps/kas-config",
					DumpPath: "/api/v1/namespaces/master-mycluster1/configmaps/kas-config",
					Filter:   ".apiServerArguments",
				},
			}
			got, _ := getResourcePaths(contentDS, contentDS, "xccdf_org.ssgproject.content_profile_platform-moderate", nil)
			Expect(got).To(Equal(expected))

			dataStreamFile.Close()
		})

		It("Gets valid resource URIs even if some of the URL references contain non-existent variable reference", func() {
			var err error
			dataStreamFile, err = os.Open("../../tests/data/ssg-ocp4-ds-new-warning-variable-nonexistent.xml")
			Expect(err).To(BeNil())

			By("parsing content without errors")
			contentDS, err = parseContent(dataStreamFile)
			Expect(err).To(BeNil())

			By("parsing content for warnings")
			expected := []utils.ResourcePath{
				{
					ObjPath:  "/apis/config.openshift.io/v1/oauths/cluster",
					DumpPath: "/apis/config.openshift.io/v1/oauths/cluster",
				},
			}
			got, _ := getResourcePaths(contentDS, contentDS, "xccdf_org.ssgproject.content_profile_platform-moderate", nil)
			Expect(got).To(Equal(expected))
			dataStreamFile.Close()
		})

		It("Gets valid resource URIs even if some of the URL references contain mal-formed go template", func() {
			var err error
			dataStreamFile, err = os.Open("../../tests/data/ssg-ocp4-ds-new-warning-variable-malformed.xml")
			Expect(err).To(BeNil())

			By("parsing content without errors")
			contentDS, err = parseContent(dataStreamFile)
			Expect(err).To(BeNil())

			By("parsing content for warnings")
			expected := []utils.ResourcePath{
				{
					ObjPath:  "/apis/config.openshift.io/v1/oauths/cluster",
					DumpPath: "/apis/config.openshift.io/v1/oauths/cluster",
				},
			}
			got, _ := getResourcePaths(contentDS, contentDS, "xccdf_org.ssgproject.content_profile_platform-moderate", nil)
			Expect(got).To(Equal(expected))
			dataStreamFile.Close()
		})

		It("Gets the appropriate resource URIs customized in a tailored profile", func() {
			var err error
			dataStreamFile, err = os.Open("../../tests/data/ssg-ocp4-ds-new-warning-variable.xml")
			Expect(err).To(BeNil())
			tpDataStreamFile, err := os.Open("../../tests/data/tailored-profile.xml")
			Expect(err).To(BeNil())

			By("parsing base profile content without errors")
			contentDS, err = parseContent(dataStreamFile)
			Expect(err).To(BeNil())

			By("parsing tailored profile content without errors")
			tpContentDS, err := parseContent(tpDataStreamFile)
			Expect(err).To(BeNil())

			By("parsing content for warnings")
			expected := []utils.ResourcePath{
				{
					ObjPath:  "/apis/config.openshift.io/v1/oauths/cluster",
					DumpPath: "/apis/config.openshift.io/v1/oauths/cluster",
				},
				{
					ObjPath:  "/api/v1/namespaces/customized/configmaps/kas-config",
					DumpPath: "/api/v1/namespaces/customized/configmaps/kas-config",
					Filter:   ".data[\"config.yaml\"] | fromjson | .apiServerArguments",
				},
			}
			_, valuesList := getResourcePaths(tpContentDS, contentDS, "xccdf_org.ssgproject.content_profile_platform-moderate", nil)
			got, _ := getResourcePaths(contentDS, contentDS, "xccdf_org.ssgproject.content_profile_platform-moderate", valuesList)
			Expect(got).To(Equal(expected))

			dataStreamFile.Close()
		})

		Context("Parsing SCAP Content with suppressed warning", func() {
			var dataStreamFile *os.File
			var contentDS *xmlquery.Node

			BeforeEach(func() {
				var err error
				dataStreamFile, err = os.Open("../../tests/data/ssg-ocp4-ds-suppressed.xml")
				Expect(err).To(BeNil())
			})
			AfterEach(func() {
				dataStreamFile.Close()
			})

			It("Gets the appropriate resource URIs", func() {
				By("parsing content without errors")
				var err error
				contentDS, err = parseContent(dataStreamFile)
				Expect(err).To(BeNil())

				By("parsing content for warnings")
				expectedItem := utils.ResourcePath{
					ObjPath:         "/apis/hypershift.openshift.io/v1beta1/namespaces/clusters/hostedclusters/None",
					DumpPath:        "/hypershift/version",
					Filter:          "[.status.version.history[].version]",
					SuppressWarning: true,
				}
				got, _ := getResourcePaths(contentDS, contentDS, "xccdf_org.ssgproject.content_profile_cis", nil)
				Expect(got).To(ContainElement(expectedItem))
			})
		})
	})

	Context("Parses the save path appropriately", func() {
		It("Parses correctly with the root being '/tmp'", func() {
			root := "/tmp"
			path := "/apis/foo"
			expectedDir := "/tmp/apis"
			expectedFile := "foo"

			dir, file, err := getSaveDirectoryAndFileName(root, path)
			Expect(err).To(BeNil())
			Expect(dir).To(Equal(expectedDir))
			Expect(file).To(Equal(expectedFile))
		})

		It("Parses correctly with the root being '/'", func() {
			root := "/"
			path := "/apis/foo/bar"
			expectedDir := "/apis/foo"
			expectedFile := "bar"

			dir, file, err := getSaveDirectoryAndFileName(root, path)
			Expect(err).To(BeNil())
			Expect(dir).To(Equal(expectedDir))
			Expect(file).To(Equal(expectedFile))
		})

		It("Parses correctly with the root being '/tmp/foo'", func() {
			root := "/tmp/foo"
			path := "/apis/foo/bar/baz"
			expectedDir := "/tmp/foo/apis/foo/bar"
			expectedFile := "baz"

			dir, file, err := getSaveDirectoryAndFileName(root, path)
			Expect(err).To(BeNil())
			Expect(dir).To(Equal(expectedDir))
			Expect(file).To(Equal(expectedFile))
		})
	})
})

var _ = Describe("Testing filtering", func() {
	Context("Filtering namespaces", func() {
		var rawns []byte
		BeforeEach(func() {
			nsFile, err := os.Open("../../tests/data/namespaces.json")
			Expect(err).To(BeNil())
			var readErr error
			rawns, readErr = io.ReadAll(nsFile)
			Expect(readErr).To(BeNil())
		})
		It("filters namespaces appropriately", func() {
			filteredOut, filterErr := filter(context.TODO(), rawns,
				`[.items[] | select((.metadata.name | startswith("openshift") | not) and (.metadata.name | startswith("kube-") | not) and .metadata.name != "default")]`)
			Expect(filterErr).To(BeNil())
			nsArr := []interface{}{}
			unmErr := json.Unmarshal(filteredOut, &nsArr)
			Expect(unmErr).To(BeNil())
			Expect(nsArr).To(HaveLen(2))
		})
	})

	Context("Filtering configmaps yaml data", func() {
		var rawcm []byte
		expectedYAML := `{"admission":{},"aggregatorConfig":{"allowedNames":null,"clientCA":"","extraHeaderPrefixes":null,"groupHeaders":null,"usernameHeaders":null},"apiServerArguments":{"audit-log-format":["json"],"audit-log-maxsize":["100"],"audit-log-path":["/var/log/openshift-apiserver/audit.log"],"audit-policy-file":["/etc/kubernetes/audit-config/policy.yaml"],"shutdown-delay-duration":["3s"]},"apiVersion":"openshiftcontrolplane.config.openshift.io/v1","auditConfig":{"auditFilePath":"","enabled":false,"logFormat":"","maximumFileRetentionDays":0,"maximumFileSizeMegabytes":0,"maximumRetainedFiles":0,"policyConfiguration":null,"policyFile":"","webHookKubeConfig":"","webHookMode":""},"cloudProviderFile":"","corsAllowedOrigins":null,"imagePolicyConfig":{"additionalTrustedCA":"","allowedRegistriesForImport":null,"externalRegistryHostnames":null,"internalRegistryHostname":"image-registry.openshift-image-registry.svc:5000","maxImagesBulkImportedPerRepository":0},"jenkinsPipelineConfig":{"autoProvisionEnabled":null,"parameters":null,"serviceName":"","templateName":"","templateNamespace":""},"kind":"OpenShiftAPIServerConfig","kubeClientConfig":{"connectionOverrides":{"acceptContentTypes":"","burst":0,"contentType":"","qps":0},"kubeConfig":"/etc/kubernetes/secrets/svc-kubeconfig/kubeconfig"},"projectConfig":{"defaultNodeSelector":"","projectRequestMessage":"","projectRequestTemplate":""},"routingConfig":{"subdomain":"apps.wenshen-hypershift.devcluster.openshift.com"},"serviceAccountOAuthGrantMethod":"","servingInfo":{"bindAddress":"","bindNetwork":"","certFile":"/etc/kubernetes/certs/serving/tls.crt","cipherSuites":["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"],"clientCA":"/etc/kubernetes/certs/client-ca/ca.crt","keyFile":"/etc/kubernetes/certs/serving/tls.key","maxRequestsInFlight":0,"minTLSVersion":"VersionTLS12","requestTimeoutSeconds":0},"storageConfig":{"ca":"/etc/kubernetes/certs/etcd-client-ca/ca.crt","certFile":"/etc/kubernetes/certs/etcd-client/etcd-client.crt","keyFile":"/etc/kubernetes/certs/etcd-client/etcd-client.key","storagePrefix":"","urls":["https://etcd-client:2379"]}}`
		BeforeEach(func() {
			cmFile, err := os.Open("../../tests/data/configmap_yaml.json")
			Expect(err).To(BeNil())
			var readErr error
			rawcm, readErr = io.ReadAll(cmFile)
			Expect(readErr).To(BeNil())
		})
		It("filters configmaps YAML data appropriately", func() {
			filteredOut, filterErr := filter(context.TODO(), rawcm,
				`.data["config.yaml"]`)
			Expect(filterErr).To(BeNil())
			Expect(string(filteredOut)).To(Equal(expectedYAML))
		})
	})

	Context("Filtering configmaps json data", func() {
		var rawcm []byte
		expectedJSON := `{"apiServerArguments":{"audit-log-format":["json"],"audit-log-maxbackup":["10"],"audit-log-maxsize":["100"],"audit-log-path":["/var/log/openshift-apiserver/audit.log"],"audit-policy-file":["/var/run/configmaps/audit/policy.yaml"],"shutdown-delay-duration":["15s"],"shutdown-send-retry-after":["true"]},"apiVersion":"openshiftcontrolplane.config.openshift.io/v1","imagePolicyConfig":{"internalRegistryHostname":"image-registry.openshift-image-registry.svc:5000"},"kind":"OpenShiftAPIServerConfig","projectConfig":{"projectRequestMessage":""},"routingConfig":{"subdomain":"apps.ci-ln-xllhdgb-76ef8.origin-ci-int-aws.dev.rhcloud.com"},"servingInfo":{"bindNetwork":"tcp","cipherSuites":["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"],"minTLSVersion":"VersionTLS12"},"storageConfig":{"urls":["https://10.0.137.27:2379","https://10.0.158.132:2379","https://10.0.204.8:2379"]}}`
		BeforeEach(func() {
			cmFile, err := os.Open("../../tests/data/configmap_json.json")
			Expect(err).To(BeNil())
			var readErr error
			rawcm, readErr = io.ReadAll(cmFile)
			Expect(readErr).To(BeNil())
		})
		It("filters configmaps JSON data appropriately", func() {
			filteredOut, filterErr := filter(context.TODO(), rawcm,
				`.data["config.yaml"] | fromjson`)
			Expect(filterErr).To(BeNil())
			Expect(string(filteredOut)).To(Equal(expectedJSON))
		})
	})

	Context("Testing errors", func() {
		It("outputs error if it can't create filter", func() {
			_, filterErr := filter(context.TODO(), []byte{},
				`.items[`)
			Expect(filterErr).ToNot(BeNil())
		})
		Context("Filtering namespaces", func() {
			var rawns []byte
			BeforeEach(func() {
				nsFile, err := os.Open("../../tests/data/namespaces.json")
				Expect(err).To(BeNil())
				var readErr error
				rawns, readErr = io.ReadAll(nsFile)
				Expect(readErr).To(BeNil())
			})

			It("skips extra results", func() {
				_, filterErr := filter(context.TODO(), rawns, `.items[]`)
				Expect(filterErr).Should(MatchError(MoreThanOneObjErr))
			})
		})
		Context("Piped Filtering", func() {
			var rawmc []byte
			BeforeEach(func() {
				nsFile, err := os.Open("../../tests/data/empty_machineconfig.json")
				Expect(err).To(BeNil())
				var readErr error
				rawmc, readErr = io.ReadAll(nsFile)
				Expect(readErr).To(BeNil())
			})
			It("retries with optional iteration on null items", func() {
				filteredOut, filterErr := filter(context.TODO(), rawmc, `[.items[] | select(.metadata.name | test("^rendered-worker-[0-9a-z]+$|^rendered-master-[0-9a-z]+$"))] | map(.spec.fips == true)`)
				Expect(filterErr).To(BeNil())
				Expect(string(filteredOut)).To(Equal("[]"))
			})
		})
		Context("PrometheusRule with empty spec", func() {
			var rawpr []byte
			BeforeEach(func() {
				prFile, err := os.Open("../../tests/data/prometheusrules_mixed.json")
				Expect(err).To(BeNil())
				var readErr error
				rawpr, readErr = io.ReadAll(prFile)
				Expect(readErr).To(BeNil())
			})
			It("retries with optional iteration and preserves valid data", func() {
				filteredOut, filterErr := filter(context.TODO(), rawpr,
					`[.items[].spec.groups[].rules[].expr]`)
				Expect(filterErr).To(BeNil())
				var exprArr []interface{}
				unmErr := json.Unmarshal(filteredOut, &exprArr)
				Expect(unmErr).To(BeNil())
				Expect(exprArr).To(HaveLen(1))
				Expect(exprArr[0]).To(Equal("apiserver_audit_error_total / apiserver_audit_event_total > 0"))
			})
			It("succeeds directly with optional iterator", func() {
				filteredOut, filterErr := filter(context.TODO(), rawpr,
					`[.items[]?.spec.groups[]?.rules[]?.expr]`)
				Expect(filterErr).To(BeNil())
				var exprArr []interface{}
				unmErr := json.Unmarshal(filteredOut, &exprArr)
				Expect(unmErr).To(BeNil())
				Expect(exprArr).To(HaveLen(1))
				Expect(exprArr[0]).To(Equal("apiserver_audit_error_total / apiserver_audit_event_total > 0"))
			})
		})
	})
})

type notFoundFetcher struct{}

func (ff *notFoundFetcher) Stream(_ context.Context, _ resourceFetcherClients) (io.ReadCloser, error) {
	return nil, errors.NewNotFound(schema.GroupResource{
		Group:    "some group",
		Resource: "some resource",
	}, "some name")
}

// mcListCall records one List call made against pagingMCClient.
type mcListCall struct {
	limit    int64
	cont     string
	returned int
	next     string
}

// pagingMCClient serves MachineConfigs the way the API server does for a
// list with limit and continue: at most Limit items per call, plus an opaque
// continue token while more remain. The controller-runtime fake client
// ignores both options, so it can't show whether a caller pages. Every List
// call is recorded.
type pagingMCClient struct {
	runtimeclient.Client
	mcs    []mcfgv1.MachineConfig
	tokens map[string]int
	calls  []mcListCall
}

func newPagingMCClient(mcs []mcfgv1.MachineConfig) *pagingMCClient {
	return &pagingMCClient{
		Client: fake.NewClientBuilder().Build(),
		mcs:    mcs,
		tokens: map[string]int{},
	}
}

func (c *pagingMCClient) List(_ context.Context, list runtimeclient.ObjectList, opts ...runtimeclient.ListOption) error {
	mcList, ok := list.(*mcfgv1.MachineConfigList)
	if !ok {
		return fmt.Errorf("pagingMCClient only lists MachineConfigs, got %T", list)
	}
	// A caller that drops the continue token would loop forever.
	if len(c.calls) > len(c.mcs) {
		return fmt.Errorf("too many List calls (%d) for %d MachineConfigs", len(c.calls), len(c.mcs))
	}

	listOpts := runtimeclient.ListOptions{}
	listOpts.ApplyOptions(opts)

	start := 0
	if listOpts.Continue != "" {
		var known bool
		if start, known = c.tokens[listOpts.Continue]; !known {
			return errors.NewBadRequest(fmt.Sprintf("unknown continue token %q", listOpts.Continue))
		}
	}
	end := len(c.mcs)
	if listOpts.Limit > 0 && start+int(listOpts.Limit) < end {
		end = start + int(listOpts.Limit)
	}

	mcList.Items = make([]mcfgv1.MachineConfig, 0, end-start)
	for i := start; i < end; i++ {
		mcList.Items = append(mcList.Items, *c.mcs[i].DeepCopy())
	}
	mcList.Continue = ""
	if end < len(c.mcs) {
		mcList.Continue = fmt.Sprintf("opaque-%d-%d", len(c.calls), end)
		c.tokens[mcList.Continue] = end
	}

	c.calls = append(c.calls, mcListCall{
		limit:    listOpts.Limit,
		cont:     listOpts.Continue,
		returned: end - start,
		next:     mcList.Continue,
	})
	return nil
}

// newManyMachineConfigs returns mcCount MachineConfigs sorted by name, as the
// API server lists them. Each one carries filesPerMC files of fileSize bytes
// and a systemd unit. The first renderedCount are named like rendered
// MachineConfigs and have FIPS and LUKS enabled, which is what the PCI-DSS
// rule machine_volume_encrypted reads.
func newManyMachineConfigs(mcCount, renderedCount, filesPerMC, fileSize int, payloadMarker string) []mcfgv1.MachineConfig {
	var payload string
	if fileSize > 0 {
		payload = strings.Repeat(payloadMarker, fileSize/len(payloadMarker)+1)[:fileSize]
	}
	mode := 0644
	unitEnabled := true
	tpm2 := true
	testDevice := "/dev/test"

	mcs := make([]mcfgv1.MachineConfig, 0, mcCount)
	for i := 0; i < mcCount; i++ {
		var name string
		rendered := i < renderedCount
		switch {
		case rendered && i%2 == 0:
			name = fmt.Sprintf("rendered-master-%032x", i)
		case rendered:
			name = fmt.Sprintf("rendered-worker-%032x", i)
		default:
			name = fmt.Sprintf("99-worker-generated-%03d", i)
		}

		unitContents := fmt.Sprintf("[Unit]\nDescription=unit %d\n[Service]\nType=oneshot\nExecStart=/bin/true\n", i)
		ign := igntypes.Config{
			Ignition: igntypes.Ignition{Version: "3.2.0"},
			Systemd: igntypes.Systemd{
				Units: []igntypes.Unit{{
					Name:     fmt.Sprintf("generated-%03d.service", i),
					Enabled:  &unitEnabled,
					Contents: &unitContents,
				}},
			},
		}
		for f := 0; f < filesPerMC; f++ {
			source := "data:," + payload
			ign.Storage.Files = append(ign.Storage.Files, igntypes.File{
				Node: igntypes.Node{Path: fmt.Sprintf("/etc/generated/%03d-%d.conf", i, f)},
				FileEmbedded1: igntypes.FileEmbedded1{
					Contents: igntypes.Resource{Source: &source},
					Mode:     &mode,
				},
			})
		}
		if rendered {
			ign.Storage.Luks = []igntypes.Luks{{
				Name:   "root",
				Device: &testDevice,
				Clevis: &igntypes.Clevis{Tpm2: &tpm2},
			}}
		}
		raw, err := json.Marshal(ign)
		Expect(err).To(BeNil())

		mcs = append(mcs, mcfgv1.MachineConfig{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: mcfgv1.MachineConfigSpec{
				FIPS:            rendered,
				KernelArguments: []string{"audit=1"},
				Config:          runtime.RawExtension{Raw: raw},
			},
		})
	}
	sort.Slice(mcs, func(a, b int) bool { return mcs[a].Name < mcs[b].Name })
	return mcs
}

var _ = Describe("Testing fetching", func() {
	var (
		fakeClients resourceFetcherClients
	)

	const (
		mcFipsFilter   = `[.items[] | select(.metadata.name | test("^[0-9]{2}-worker-fips$|^[0-9]{2}-master-fips$"))]|map(.spec.fips == true)`
		mcClevisFilter = `[.items[] | select(.metadata.name | test("^[0-9]{2}-worker-fips$|^[0-9]{2}-master-fips$"))]|map(.spec.config.storage.luks[0].clevis != null)`
	)

	Context("handle fetch failures", func() {
		It("fetches and stores 404s", func() {
			fakeDispatcher := func(uri string) resourceStreamer {
				return &notFoundFetcher{}
			}

			files, warnings, err := fetch(context.TODO(),
				fakeDispatcher,
				resourceFetcherClients{},
				[]utils.ResourcePath{{DumpPath: "key"}})

			Expect(err).To(BeNil())
			Expect(files).To(HaveLen(1))
			Expect(string(files["key"])).To(Equal("# kube-api-error=NotFound"))
			Expect(warnings).To(HaveLen(1))
			Expect(warnings[0]).To(Equal("could not fetch : some resource.some group \"some name\" not found"))
		})
	})

	Context("handle fetch failures with suppressed warning", func() {
		It("fetches and discard 404s", func() {
			fakeDispatcher := func(uri string) resourceStreamer {
				return &notFoundFetcher{}
			}

			files, warnings, err := fetch(context.TODO(),
				fakeDispatcher,
				resourceFetcherClients{},
				[]utils.ResourcePath{{DumpPath: "key", SuppressWarning: true}})

			Expect(err).To(BeNil())
			Expect(files).To(HaveLen(1))
			Expect(string(files["key"])).To(Equal("# kube-api-error=NotFound"))
			Expect(warnings).To(HaveLen(0))
		})
	})
	Context("handle Machine Config fetching", func() {
		var filter string
		var files map[string][]byte
		var warnings []string
		var err error

		JustBeforeEach(func() {
			testDevice := "/dev/test"

			fakeIgn := igntypes.Config{
				Ignition: igntypes.Ignition{
					Version: "3.2.0",
				},
				Storage: igntypes.Storage{
					Luks: []igntypes.Luks{
						{
							Device: &testDevice,
							Clevis: &igntypes.Clevis{},
						},
					},
					Files: []igntypes.File{
						{
							Node: igntypes.Node{
								Path: "/etc/foo",
							},
						},
					},
				},
			}

			rawFakeIgn, err := json.Marshal(fakeIgn)
			Expect(err).To(BeNil())

			mcList := mcfgv1.MachineConfigList{Items: []mcfgv1.MachineConfig{
				{
					// regression test for RHBZ #2117268
					ObjectMeta: metav1.ObjectMeta{
						Name:      "99-no-ign-mc",
						Namespace: common.GetComplianceOperatorNamespace(),
					},
					Spec: mcfgv1.MachineConfigSpec{
						KernelArguments: []string{"audit=1"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "99-worker-fips",
						Namespace: common.GetComplianceOperatorNamespace(),
					},
					Spec: mcfgv1.MachineConfigSpec{
						FIPS: true,
						Config: runtime.RawExtension{
							Raw: rawFakeIgn,
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "99-master-fips",
						Namespace: common.GetComplianceOperatorNamespace(),
					},
					Spec: mcfgv1.MachineConfigSpec{
						FIPS: false,
						Config: runtime.RawExtension{
							Raw: rawFakeIgn,
						},
					},
				},
			}}

			scheme := scheme.Scheme
			scheme.AddKnownTypes(mcfgv1.SchemeGroupVersion, &mcList, &mcList.Items[0])

			client := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(&mcList).Build()
			fakeClients = resourceFetcherClients{client: client}

			fetchMcResources := []utils.ResourcePath{
				{
					ObjPath:  "/apis/machineconfiguration.openshift.io/v1/machineconfigs",
					Filter:   filter,
					DumpPath: "mcDumpPath",
				},
			}

			files, warnings, err = fetch(context.TODO(), getStreamerFn, fakeClients, fetchMcResources)
		})
		When("MC filters FIPS", func() {
			BeforeEach(func() {
				filter = mcFipsFilter
			})

			It("Keeps the FIPS attributes intact", func() {
				Expect(err).To(BeNil())
				Expect(files).To(HaveLen(1))
				Expect(string(files["mcDumpPath"])).To(Equal("[false,true]"))
				Expect(warnings).To(HaveLen(0))
			})
		})
		When("MC filters Clevis", func() {
			BeforeEach(func() {
				filter = mcClevisFilter
			})

			It("Keeps the Clevis attributes intact", func() {
				Expect(err).To(BeNil())
				Expect(files).To(HaveLen(1))
				Expect(string(files["mcDumpPath"])).To(Equal("[true,true]"))
				Expect(warnings).To(HaveLen(0))
			})
		})
	})

	// OCP-53667 checks that a PCI-DSS platform scan still finishes on a
	// cluster with 150 more MachineConfigs. The api-resource-collector used to
	// list every MachineConfig in one request and keep their file contents,
	// which got it OOM-killed on large clusters (OCPBUGSM-45245). mcStreamer
	// now lists them in pages and drops storage.files from each page before
	// keeping it.
	Context("handle a large number of Machine Configs", func() {
		const (
			mcURI         = "/apis/machineconfiguration.openshift.io/v1/machineconfigs"
			mcCount       = 150
			renderedCount = 10
			filesPerMC    = 4
			fileSize      = 64 * 1024
			// mcStreamer.Stream lists MachineConfigs 5 at a time
			mcPageSize    = 5
			payloadMarker = "compliance-operator-file-payload-"
			// machine_volume_encrypted, in both PCI-DSS profiles, reads
			// all MachineConfigs through these two filters.
			pciFipsFilter = `[.items[] | select(.metadata.name | test("^rendered-worker-[0-9a-z]+$|^rendered-master-[0-9a-z]+$"))] | map(.spec.fips == true)`
			pciLuksFilter = `[.items[] | select(.metadata.name | test("^rendered-worker-[0-9a-z]+$|^rendered-master-[0-9a-z]+$"))] | map(.spec.config.storage.luks[0].clevis != null)`
		)

		streamMCs := func(mcs []mcfgv1.MachineConfig) ([]byte, *pagingMCClient) {
			client := newPagingMCClient(mcs)
			files, warnings, err := fetch(context.TODO(), getStreamerFn,
				resourceFetcherClients{client: client},
				[]utils.ResourcePath{{ObjPath: mcURI, DumpPath: "mcs"}})
			Expect(err).To(BeNil())
			Expect(warnings).To(BeEmpty())
			Expect(files).To(HaveKey("mcs"))
			return files["mcs"], client
		}

		It("lists them in pages and keeps none of their file contents", func() {
			mcs := newManyMachineConfigs(mcCount, renderedCount, filesPerMC, fileSize, payloadMarker)
			listedBytes := 0
			for i := range mcs {
				listedBytes += len(mcs[i].Spec.Config.Raw)
			}
			body, client := streamMCs(mcs)
			fmt.Fprintf(GinkgoWriter, "%d MachineConfigs: %d bytes of Ignition config listed, %d bytes kept\n",
				mcCount, listedBytes, len(body))

			By("listing them 5 at a time and following the continue token to the end")
			Expect(client.calls).To(HaveLen(mcCount / mcPageSize))
			for i, call := range client.calls {
				Expect(call.limit).To(Equal(int64(mcPageSize)), "limit of List call %d", i)
				Expect(call.returned).To(Equal(mcPageSize), "items returned by List call %d", i)
				if i == 0 {
					Expect(call.cont).To(BeEmpty())
				} else {
					Expect(call.cont).To(Equal(client.calls[i-1].next), "continue token of List call %d", i)
				}
			}
			Expect(client.calls[len(client.calls)-1].next).To(BeEmpty())

			By("keeping every MachineConfig once, in the order they were listed")
			kept := mcfgv1.MachineConfigList{}
			Expect(json.Unmarshal(body, &kept)).To(Succeed())
			Expect(kept.Items).To(HaveLen(mcCount))
			for i := range kept.Items {
				Expect(kept.Items[i].Name).To(Equal(mcs[i].Name))
			}

			By("dropping storage.files and keeping the rest of each MachineConfig")
			Expect(bytes.Contains(body, []byte(payloadMarker))).To(BeFalse(), "file contents were kept")
			for i := range kept.Items {
				keptCfg := map[string]interface{}{}
				Expect(json.Unmarshal(kept.Items[i].Spec.Config.Raw, &keptCfg)).To(Succeed())
				listedCfg := map[string]interface{}{}
				Expect(json.Unmarshal(mcs[i].Spec.Config.Raw, &listedCfg)).To(Succeed())

				Expect(keptCfg["storage"]).NotTo(HaveKey("files"), "files of %s", kept.Items[i].Name)
				Expect(keptCfg["systemd"]).To(Equal(listedCfg["systemd"]), "systemd units of %s", kept.Items[i].Name)
				Expect(kept.Items[i].Spec.FIPS).To(Equal(mcs[i].Spec.FIPS))
				Expect(kept.Items[i].Spec.KernelArguments).To(Equal(mcs[i].Spec.KernelArguments))
			}

			By("keeping the same output whatever the size of the files")
			bodyEmptyFiles, _ := streamMCs(newManyMachineConfigs(mcCount, renderedCount, filesPerMC, 0, payloadMarker))
			Expect(bytes.Equal(body, bodyEmptyFiles)).To(BeTrue(),
				"output with %d-byte files is %d bytes, with empty files %d bytes", fileSize, len(body), len(bodyEmptyFiles))

			By("keeping what machine_volume_encrypted reads")
			allTrue := "[" + strings.TrimSuffix(strings.Repeat("true,", renderedCount), ",") + "]"
			for _, f := range []string{pciFipsFilter, pciLuksFilter} {
				out, err := filter(context.TODO(), body, f)
				Expect(err).To(BeNil())
				Expect(string(out)).To(Equal(allTrue), "result of filter %s", f)
			}
		})
	})
})
