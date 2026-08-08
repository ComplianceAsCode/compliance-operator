package manager

import (
	"context"
	"encoding/json"
	"io"
	"os"

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

})
