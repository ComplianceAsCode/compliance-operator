package tests

import (
	"context"
	"log"
	"time"

	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/openshift/osde2e-example-test-harness/pkg/metadata"
	apiextclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	extscheme "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/scheme"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	cached "k8s.io/client-go/discovery/cached"
	"k8s.io/client-go/kubernetes"
	cgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	dynclient "sigs.k8s.io/controller-runtime/pkg/client"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
)

var _ = ginkgo.Describe("ROSA Compliance Tests", func() {
	var config *rest.Config

	ginkgo.BeforeEach(func() {
		var err error
		config, err = rest.InClusterConfig()
		Expect(err).NotTo(HaveOccurred(), "unable to load in cluster config")

		// Install the Compliance Operator and wait for it to become available.

		// Wait for the profile bundles to get parsed and loaded by the
		// operator (this is necessary before we can perform any scans).
	})

	ginkgo.It("Ensure Compliance Operator CRDs exist", func() {
		client, err := apiextclientset.NewForConfig(config)
		Expect(err).NotTo(HaveOccurred(), "failed to create clientset")

		// Make sure the CRD exists
		result, err := client.ApiextensionsV1().CustomResourceDefinitions().Get(context.TODO(), "profiles.compliance.openshift.io", v1.GetOptions{})
		if err != nil {
			log.Printf("CRD not found: %v", err.Error())
			metadata.Instance.FoundCRD = false
		} else {
			log.Printf("CRD found: %v", result.GetName())
			metadata.Instance.FoundCRD = true
		}

		Expect(err).NotTo(HaveOccurred(), "failed to get the crd")
	})

	ginkgo.It("Is PCI-DSS compliant", func() {
		k8sClient, err := kubernetes.NewForConfig(config)
		Expect(err).NotTo(HaveOccurred(), "unable to create client")

		scheme := runtime.NewScheme()
		err = cgoscheme.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred(), "failed to load kubernetes runtime scheme: %s", err)
		err = extscheme.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred(), "failed to load API extension runtime scheme: %s", err)

		cachedDiscoveryClient := cached.NewMemCacheClient(k8sClient.Discovery())
		restMapper := restmapper.NewDeferredDiscoveryRESTMapper(cachedDiscoveryClient)
		client, err := dynclient.New(config, dynclient.Options{Scheme: scheme, Mapper: restMapper})
		Expect(err).NotTo(HaveOccurred(), "failed to create client from config: %s", err)

		namespace := "openshift-compliance"
		bindingName := "pci-dss"
		platformScanName := "ocp4-pci-dss"
		nodeScanName := "ocp4-pci-dss-node"
		retryInterval := time.Second * 5
		timeout := time.Minute * 15

		// Create a ScanSettingBinding that scans the ROSA cluster
		// using the default PCI-DSS profile.
		ssb := compv1alpha1.ScanSettingBinding{
			ObjectMeta: v1.ObjectMeta{
				Name:      bindingName,
				Namespace: namespace,
			},
			Profiles: []compv1alpha1.NamedObjectReference{
				{
					Name:     platformScanName,
					Kind:     "Profile",
					APIGroup: "compliance.openshift.io/v1alpha1",
				},
				{
					Name:     nodeScanName,
					Kind:     "Profile",
					APIGroup: "compliance.openshift.io/v1alpha1",
				},
			},
			SettingsRef: &compv1alpha1.NamedObjectReference{
				Name:     "default",
				Kind:     "ScanSetting",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
		}
		err = client.Create(context.TODO(), &ssb)
		Expect(err).NotTo(HaveOccurred(), "failed to create ScanSettingBinding: %s: %s", bindingName, err)

		// Wait for the scan to finish.
		scan := &compv1alpha1.ComplianceScan{}
		err = wait.Poll(retryInterval, timeout, func() (bool, error) {
			lastErr := client.Get(context.TODO(), types.NamespacedName{Name: bindingName, Namespace: namespace}, scan)
			if lastErr != nil {
				if apierrors.IsNotFound(lastErr) {
					log.Printf("Waiting for availability of ComplianceScan %s\n", bindingName)
					return false, nil
				}
				log.Printf("Retrying. Got error: %v\n", lastErr)
				return false, nil
			}

			if scan.Status.Phase == compv1alpha1.PhaseDone {
				return true, nil
			}
			log.Printf("Waiting for run of ComplianceScan %s to complete (%s)\n", bindingName, scan.Status.Phase)
			return false, nil
		})
		Expect(err).NotTo(HaveOccurred(), "timed out waiting for ComplianceScan %s to complete", scan.Name, err)

		Expect(scan.Status.Result).To(Equal(compv1alpha1.ResultCompliant))
	})
})
