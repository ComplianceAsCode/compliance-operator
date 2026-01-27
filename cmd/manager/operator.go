package manager

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"os"
	"reflect"
	goruntime "runtime"
	"strings"

	"github.com/go-logr/logr"
	configv1 "github.com/openshift/api/config/v1"
	log "github.com/sirupsen/logrus"
	"go.uber.org/zap/zapcore"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/healthz"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis"
	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/common"
	ctrlMetrics "github.com/ComplianceAsCode/compliance-operator/pkg/controller/metrics"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
	"github.com/ComplianceAsCode/compliance-operator/pkg/xccdf"
	"github.com/ComplianceAsCode/compliance-operator/version"
	ocpapi "github.com/openshift/api"
	mcfgapi "github.com/openshift/api/machineconfiguration"
	monitoring "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	monclientv1 "github.com/prometheus-operator/prometheus-operator/pkg/client/versioned/typed/monitoring/v1"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	kerr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	clusterv1alpha1 "open-cluster-management.io/api/cluster/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

var OperatorCmd = &cobra.Command{
	Use:   "operator",
	Short: "The compliance-operator command",
	Long:  `An operator that issues compliance checks and their lifecycle.`,
	Run:   RunOperator,
}

var (
	operatorScheme = runtime.NewScheme()
)

func init() {
	defineOperatorFlags(OperatorCmd)
	utilruntime.Must(clientgoscheme.AddToScheme(operatorScheme))

	utilruntime.Must(compv1alpha1.SchemeBuilder.AddToScheme(operatorScheme))
	//+kubebuilder:scaffold:scheme
}

type PlatformType string

const (
	PlatformOpenShift        PlatformType = "OpenShift"
	PlatformEKS              PlatformType = "EKS"
	PlatformROSA             PlatformType = "ROSA"
	PlatformGeneric          PlatformType = "Generic"
	PlatformHyperShift       PlatformType = "HyperShift"
	PlatformOpenShiftOnPower PlatformType = "OpenShiftOnPower"
	PlatformOpenShiftOnZ     PlatformType = "OpenShiftOnZ"
	PlatformUnknown          PlatformType = "Unknown"
)

// Change below variables to serve metrics on different host or port.
var (
	setupLog                   = logf.Log.WithName("setup")
	metricsAddr                string
	enableLeaderElection       bool
	probeAddr                  string
	metricsHost                      = "0.0.0.0"
	metricsServiceName               = "metrics"
	metricsPort                int32 = 8383
	defaultProductsPerPlatform       = map[PlatformType][]string{
		PlatformOpenShift: {
			"rhcos4",
			"ocp4",
		},
		PlatformOpenShiftOnPower: {
			"rhcos4",
			"ocp4",
		},
		PlatformOpenShiftOnZ: {"ocp4"},
		PlatformEKS: {
			"eks",
		},
		PlatformHyperShift: {
			"rhcos4",
			"ocp4",
		},
		PlatformROSA: {
			"rhcos4",
			"ocp4",
		},
	}

	defaultRolesPerPlatform = map[PlatformType][]string{
		PlatformOpenShift: {
			"master",
			"worker",
		},
		PlatformOpenShiftOnPower: {
			"master",
			"worker",
		},
		PlatformOpenShiftOnZ: {
			"master",
			"worker",
		},
		PlatformGeneric: {
			compv1alpha1.AllRoles,
		},
		PlatformHyperShift: {
			"worker",
		},
		PlatformROSA: {
			"worker",
		},
	}

	defaultAutoRemediationPerPlatform = map[PlatformType]bool{
		PlatformOpenShift:        true,
		PlatformOpenShiftOnPower: true,
		PlatformOpenShiftOnZ:     true,
		PlatformEKS:              false,
		PlatformGeneric:          false,
		PlatformHyperShift:       true,
		PlatformROSA:             false,
	}
	serviceMonitorBearerTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	serviceMonitorTLSCAFile       = "/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt"
	alertName                     = "compliance"
)

const (
	defaultScanSettingsName          = "default"
	defaultAutoApplyScanSettingsName = "default-auto-apply"
	// Run scan every day at 1am
	defaultScanSettingsSchedule = "0 1 * * *"
)

func defineOperatorFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("skip-metrics", false,
		"Skips adding metrics.")
	cmd.Flags().String("platform", "OpenShift",
		"Specifies the Platform the Compliance Operator is running on. "+
			"This will affect the defaults created.")
	flag.StringVar(&metricsAddr, "metrics-bind-address", fmt.Sprintf(":%d", metricsPort), "The address the metric endpoint binds to. This option is hard-coded to the default and is left for compatibility.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")

	// Add the zap logger flag set to the CLI. The flag set must
	// be added before calling pflag.Parse().
	flags := cmd.Flags()

	// Add flags registered by imported packages (e.g. glog and
	// controller-runtime)
	flags.AddGoFlagSet(flag.CommandLine)

}

func printVersion() {
	setupLog.Info(fmt.Sprintf("Go Version: %s", goruntime.Version()))
	setupLog.Info(fmt.Sprintf("Go OS/Arch: %s/%s", goruntime.GOOS, goruntime.GOARCH))
	setupLog.Info(fmt.Sprintf("Compliance Operator Version: %v", version.Version))
}

func operatorTimeEncoder() zapcore.TimeEncoder {
	return zapcore.ISO8601TimeEncoder
}

func operatorLogger() logr.Logger {
	return zap.New(zap.UseFlagOptions(&zap.Options{
		TimeEncoder: operatorTimeEncoder(),
	}))
}

func RunOperator(cmd *cobra.Command, args []string) {
	flags := cmd.Flags()
	flags.AddGoFlagSet(flag.CommandLine)
	flags.Parse(args)

	logf.SetLogger(operatorLogger())

	printVersion()

	namespace, err := common.GetWatchNamespace()
	if err != nil {
		setupLog.Error(err, "Failed to get watch namespace")
		os.Exit(1)
	}
	if namespace != "" {
		setupLog.Info("Watching", "namespace", namespace)
		// Force watch of compliance-operator-namespace so it gets added to the cache
		if !strings.Contains(namespace, common.GetComplianceOperatorNamespace()) {
			namespace = namespace + "," + common.GetComplianceOperatorNamespace()
		}
	} else {
		setupLog.Info("Watching all namespaces")
	}

	// Unused, but kept until we decide what to do with multi-namespace support. See the creation of `mgr` below for
	// the actual operator options configuration.
	c := cache.Options{DefaultNamespaces: map[string]cache.Config{namespace: {}}}
	options := manager.Options{
		Cache:   c,
		Metrics: metricsserver.Options{BindAddress: fmt.Sprintf("%s:%d", metricsHost, metricsPort)},
	}
	var namespaceList []string

	if namespace != "" {
		namespaceList = strings.Split(namespace, ",")
		// Add support for MultiNamespace set in WATCH_NAMESPACE (e.g ns1,ns2)
		// Note that this is not intended to be used for excluding namespaces, this is better done via a Predicate
		// Also note that you may face performance issues when using this with a high number of namespaces.
		// More Info: https://godoc.org/github.com/kubernetes-sigs/controller-runtime/pkg/cache#MultiNamespacedCacheBuilder
		if strings.Contains(namespace, ",") {
			// These are not applied because of the non-use of the `options` variable, so multi-namespace is probably non-functional.
			for _, ns := range namespaceList {
				options.Cache.DefaultNamespaces[ns] = cache.Config{}
			}
		}
	} else {
		// NOTE(jaosorior): This will be used to set up the needed defaults
		namespaceList = []string{common.GetComplianceOperatorNamespace()}
	}

	// Get a config to talk to the apiserver
	cfg, err := config.GetConfig()
	if err != nil {
		setupLog.Error(err, "")
		os.Exit(1)
	}

	ctx := context.TODO()
	kubeClient := kubernetes.NewForConfigOrDie(cfg)
	monitoringClient := monclientv1.NewForConfigOrDie(cfg)

	disableHTTP2 := func(c *tls.Config) {
		c.NextProtos = []string{"http/1.1"}
	}
	webhookServerOptions := webhook.Options{
		Port:    9443,
		TLSOpts: []func(config *tls.Config){disableHTTP2},
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Cache:                  c,
		Scheme:                 operatorScheme,
		Metrics:                metricsserver.Options{BindAddress: fmt.Sprintf("%s:%d", metricsHost, metricsPort)},
		WebhookServer:          webhook.NewServer(webhookServerOptions),
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "81473831.openshift.io", // operator-sdk generated this for us
	})
	if err != nil {
		setupLog.Error(err, "unable to create manager")
		os.Exit(1)
	}

	setupLog.Info("Registering Components.")
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	mgrscheme := mgr.GetScheme()
	// Setup Scheme for all resources
	if err := apis.AddToScheme(mgrscheme); err != nil {
		setupLog.Error(err, "")
		os.Exit(1)
	}
	if err := mcfgapi.Install(mgrscheme); err != nil {
		setupLog.Error(err, "")
		os.Exit(1)
	}

	if err := ocpapi.Install(mgrscheme); err != nil {
		setupLog.Info("Couldn't install OCP API. This is not fatal though.")
		setupLog.Error(err, "")
	}

	// Index the ID field of Checks
	if err := mgr.GetFieldIndexer().IndexField(ctx, &compv1alpha1.ComplianceCheckResult{}, compv1alpha1.ComplianceRemediationDependencyField, func(rawObj client.Object) []string {
		check, ok := rawObj.(*compv1alpha1.ComplianceCheckResult)
		if !ok {
			return []string{}
		}
		return []string{check.ID}
	}); err != nil {
		setupLog.Error(err, "Error indexing the ID field of ComplianceCheckResult")
		os.Exit(1)
	}

	met := ctrlMetrics.New()
	if err := met.Register(); err != nil {
		setupLog.Error(err, "Error registering metrics")
		os.Exit(1)
	}

	si, getSIErr := getSchedulingInfo(ctx, mgr.GetAPIReader())
	if getSIErr != nil {
		setupLog.Error(getSIErr, "Getting control plane scheduling info")
		os.Exit(1)
	}

	// Setup all Controllers
	if err := controller.AddToManager(mgr, met, si, kubeClient); err != nil {
		setupLog.Error(err, "")
		os.Exit(1)
	}

	infra := &configv1.Infrastructure{}
	if err := kubeClient.RESTClient().Get().RequestURI("/apis/config.openshift.io/v1/infrastructures/cluster").Do(ctx).Into(infra); err != nil {
		setupLog.Info("Couldn't get Infrastructure. This is not fatal though.")
		setupLog.Error(err, "")
	} else {
		// Set environment variables for the controlPlaneTopology
		os.Setenv("CONTROL_PLANE_TOPOLOGY", string(infra.Status.ControlPlaneTopology))
	}

	// We need to set PLATFORM env var if the PLATFORM flag is set
	pflag := os.Getenv("PLATFORM")
	if pflag == "" {
		clusterClaim := &clusterv1alpha1.ClusterClaim{}
		if err := kubeClient.RESTClient().Get().RequestURI("/apis/cluster.open-cluster-management.io/v1alpha1/clusterclaims/product.open-cluster-management.io").Do(ctx).Into(clusterClaim); err != nil {
			setupLog.Info("Couldn't get ClusterClaim. This is not fatal though.")
			setupLog.Error(err, "")
		} else {
			// check the value of the clusterClaim
			if clusterClaim.Spec.Value != "" {
				pflag = clusterClaim.Spec.Value
				os.Setenv("PLATFORM", pflag)
			}
		}
	}

	if pflag == "" {
		pflag, _ = flags.GetString("platform")
		os.Setenv("PLATFORM", pflag)
	}

	platform := getValidPlatform(pflag)

	skipMetrics, _ := flags.GetBool("skip-metrics")
	// We only support these metrics in OpenShift (at the moment)
	if (platform == PlatformOpenShift || platform == PlatformOpenShiftOnPower || platform == PlatformOpenShiftOnZ) && !skipMetrics {
		// Add the Metrics Service
		addMetrics(ctx, cfg, kubeClient, monitoringClient)
	}

	if err := ensureDefaultProfileBundles(ctx, mgr.GetClient(), namespaceList, platform); err != nil {
		setupLog.Error(err, "Error creating default ProfileBundles.")
		os.Exit(1)
	}

	if err := ensureDefaultScanSettings(ctx, mgr.GetClient(), namespaceList, platform, si); err != nil {
		setupLog.Error(err, "Error creating default ScanSettings.")
		os.Exit(1)
	}

	setupLog.Info("Starting the Cmd.")

	// Start the Cmd
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "Manager exited non-zero")
		os.Exit(1)
	}
}

func getValidPlatform(p string) PlatformType {
	arch := goruntime.GOARCH
	switch {
	case strings.EqualFold(p, string(PlatformOpenShift)):
		switch {
		case strings.EqualFold(arch, "ppc64le"):
			return PlatformOpenShiftOnPower
		case strings.EqualFold(arch, "s390x"):
			return PlatformOpenShiftOnZ
		default:
			return PlatformOpenShift
		}
	case strings.EqualFold(p, string(PlatformROSA)):
		return PlatformROSA
	case strings.EqualFold(p, string(PlatformEKS)):
		return PlatformEKS
	case strings.EqualFold(p, string(PlatformHyperShift)):
		return PlatformHyperShift
	case strings.EqualFold(p, string(PlatformROSA)):
		return PlatformROSA
	case strings.EqualFold(p, string(PlatformGeneric)):
		return PlatformGeneric

	default:
		return PlatformUnknown
	}
}

// addMetrics will create the Services and Service Monitors to allow the operator export the metrics by using
// the Prometheus operator
func addMetrics(ctx context.Context, cfg *rest.Config, kClient *kubernetes.Clientset,
	mClient *monclientv1.MonitoringV1Client) {
	// Get the namespace the operator is currently deployed in.
	operatorNs := common.GetComplianceOperatorNamespace()

	// Create the metrics service and make sure the service-secret is available
	metricsService, err := ensureMetricsServiceAndSecret(ctx, kClient, operatorNs)
	if err != nil {
		setupLog.Error(err, "Error creating metrics service/secret")
		os.Exit(1)
	}

	if err := handleServiceMonitor(ctx, cfg, mClient, operatorNs, metricsService); err != nil {
		log.Error(err, "Error creating ServiceMonitor")
		os.Exit(1)
	}

	if err := createNonComplianceAlert(ctx, mClient, operatorNs); err != nil {
		setupLog.Error(err, "Error creating PrometheusRule")
		os.Exit(1)
	}
}

func operatorMetricService(ns string) *v1.Service {
	return &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"name": "compliance-operator",
			},
			Annotations: map[string]string{
				"service.beta.openshift.io/serving-cert-secret-name": "compliance-operator-serving-cert",
			},
			Name:      metricsServiceName,
			Namespace: ns,
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				{
					Name:       metricsServiceName,
					Port:       metricsPort,
					TargetPort: intstr.FromInt(int(metricsPort)),
					Protocol:   v1.ProtocolTCP,
				},
				{
					Name:       ctrlMetrics.ControllerMetricsServiceName,
					Port:       ctrlMetrics.ControllerMetricsPort,
					TargetPort: intstr.FromInt(ctrlMetrics.ControllerMetricsPort),
					Protocol:   v1.ProtocolTCP,
				},
			},
			Selector: map[string]string{
				"name": "compliance-operator",
			},
			Type: v1.ServiceTypeClusterIP,
		},
	}
}

func ensureMetricsServiceAndSecret(ctx context.Context, kClient *kubernetes.Clientset, ns string) (*v1.Service, error) {
	var returnService *v1.Service
	var err error
	newService := operatorMetricService(ns)
	createdService, err := kClient.CoreV1().Services(ns).Create(ctx, newService, metav1.CreateOptions{})
	if err != nil && !kerr.IsAlreadyExists(err) {
		return nil, err
	}
	if kerr.IsAlreadyExists(err) {
		curService, getErr := kClient.CoreV1().Services(ns).Get(ctx, newService.Name, metav1.GetOptions{})
		if getErr != nil {
			return nil, getErr
		}
		returnService = curService

		// Needs update?
		if !reflect.DeepEqual(curService.Spec, newService.Spec) {
			serviceCopy := curService.DeepCopy()
			serviceCopy.Spec = newService.Spec

			// OCP-4.6 only - Retain ClusterIP from the current service in case we overwrite it when copying the updated
			// service. Avoids "Error creating metrics service/secret","error":"Service \"metrics\" is invalid: spec.clusterIP:
			// Invalid value: \"\": field is immutable","stacktrace"...
			if len(serviceCopy.Spec.ClusterIP) == 0 {
				serviceCopy.Spec.ClusterIP = curService.Spec.ClusterIP
			}

			updatedService, updateErr := kClient.CoreV1().Services(ns).Update(ctx, serviceCopy, metav1.UpdateOptions{})
			if updateErr != nil {
				return nil, updateErr
			}
			returnService = updatedService
		}
	} else {
		returnService = createdService
	}

	// Ensure the serving-cert secret for metrics is available, we have to exit and restart if not
	if _, err := kClient.CoreV1().Secrets(ns).Get(ctx, "compliance-operator-serving-cert", metav1.GetOptions{}); err != nil {
		if kerr.IsNotFound(err) {
			return nil, errors.New("compliance-operator-serving-cert not found - restarting, as the service may have just been created")
		} else {
			return nil, err
		}
	}

	return returnService, nil
}

func getSchedulingInfo(ctx context.Context, cli client.Reader) (utils.CtlplaneSchedulingInfo, error) {
	key := types.NamespacedName{
		Name:      common.GetComplianceOperatorName(),
		Namespace: common.GetComplianceOperatorNamespace(),
	}
	pod := corev1.Pod{}
	setupLog.Info("Deriving scheduling info from pod",
		"Pod.Name", key.Name, "Pod.Namespace", key.Namespace)
	if err := cli.Get(ctx, key, &pod); err != nil {
		return utils.CtlplaneSchedulingInfo{}, err
	}

	sel := pod.Spec.NodeSelector
	if sel == nil {
		sel = map[string]string{}
	}
	tol := pod.Spec.Tolerations
	if tol == nil {
		tol = []corev1.Toleration{}
	}

	return utils.CtlplaneSchedulingInfo{
		Selector:    sel,
		Tolerations: tol,
	}, nil
}

func ensureDefaultProfileBundles(
	ctx context.Context,
	crclient client.Client,
	namespaceList []string,
	platform PlatformType,
) error {
	pbimg := utils.GetComponentImage(utils.CONTENT)
	var lastErr error
	defaultProducts, isSupported := defaultProductsPerPlatform[platform]
	if !isSupported {
		setupLog.Info("No ProfileBundle defaults for unknown product." +
			" Skipping defaults creation.")
		return nil
	}
	for _, prod := range defaultProducts {
		for _, ns := range namespaceList {
			pb := &compv1alpha1.ProfileBundle{
				ObjectMeta: metav1.ObjectMeta{
					Name:      prod,
					Namespace: ns,
				},
				Spec: compv1alpha1.ProfileBundleSpec{
					ContentImage: pbimg,
					ContentFile:  xccdf.GetContentFileName(prod),
				},
			}
			setupLog.Info("Ensuring ProfileBundle is available",
				"ProfileBundle.Name", pb.GetName(),
				"ProfileBundle.Namespace", pb.GetNamespace())
			if err := ensureSupportedProfileBundle(ctx, crclient, pb); err != nil {
				lastErr = err
			}
		}
	}
	return lastErr
}

func ensureSupportedProfileBundle(ctx context.Context, crclient client.Client, pb *compv1alpha1.ProfileBundle) error {
	createErr := crclient.Create(ctx, pb)
	if k8serrors.IsAlreadyExists(createErr) {
		return crclient.Patch(ctx, pb, client.Merge)
	} else if createErr != nil {
		return createErr
	}
	return nil
}

func ensureDefaultScanSettings(
	ctx context.Context,
	crclient client.Client,
	namespaceList []string,
	platform PlatformType,
	si utils.CtlplaneSchedulingInfo,
) error {
	var lastErr error
	for _, ns := range namespaceList {
		roles := getDefaultRoles(platform)
		autoRemediationEnabled := defaultAutoRemediationPerPlatform[platform]
		d := &compv1alpha1.ScanSetting{
			ObjectMeta: metav1.ObjectMeta{
				Name:      defaultScanSettingsName,
				Namespace: ns,
			},
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				RawResultStorage: compv1alpha1.RawResultStorageSettings{
					NodeSelector: si.Selector,
					Tolerations:  si.Tolerations,
				},
			},
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				Schedule: defaultScanSettingsSchedule,
			},
			Roles: roles,
		}
		setupLog.Info("Ensuring ScanSetting is available",
			"ScanSetting.Name", d.GetName(),
			"ScanSetting.Namespace", d.GetNamespace())
		derr := crclient.Create(ctx, d)
		if !k8serrors.IsAlreadyExists(derr) {
			lastErr = derr
		}
		if autoRemediationEnabled {
			a := &compv1alpha1.ScanSetting{
				ObjectMeta: metav1.ObjectMeta{
					Name:      defaultAutoApplyScanSettingsName,
					Namespace: ns,
				},
				ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
					RawResultStorage: compv1alpha1.RawResultStorageSettings{
						NodeSelector: si.Selector,
						Tolerations:  si.Tolerations,
					},
				},
				ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
					AutoApplyRemediations:  true,
					AutoUpdateRemediations: true,
					Schedule:               defaultScanSettingsSchedule,
				},
				Roles: roles,
			}
			setupLog.Info("Ensuring ScanSetting is available",
				"ScanSetting.Name", d.GetName(),
				"ScanSetting.Namespace", d.GetNamespace())
			aerr := crclient.Create(ctx, a)
			if !k8serrors.IsAlreadyExists(aerr) {
				lastErr = aerr
			}
		}
	}
	return lastErr
}

func getDefaultRoles(platform PlatformType) []string {
	roles, hasSpecific := defaultRolesPerPlatform[platform]
	if hasSpecific {
		return roles
	}
	return defaultRolesPerPlatform[PlatformGeneric]
}

func generateOperatorServiceMonitor(service *v1.Service, namespace string) *monitoring.ServiceMonitor {
	serviceMonitor := GenerateServiceMonitor(service)
	m := "metrics." + namespace + ".svc"
	for i := range serviceMonitor.Spec.Endpoints {
		if serviceMonitor.Spec.Endpoints[i].Port == ctrlMetrics.ControllerMetricsServiceName {
			serviceMonitor.Spec.Endpoints[i].Path = ctrlMetrics.HandlerPath
			serviceMonitor.Spec.Endpoints[i].Scheme = "https"
			serviceMonitor.Spec.Endpoints[i].TLSConfig = &monitoring.TLSConfig{
				SafeTLSConfig: monitoring.SafeTLSConfig{
					ServerName: &m,
				},
				CAFile: serviceMonitorTLSCAFile,
			}
		}
	}
	return serviceMonitor
}

// createOrUpdateServiceMonitor creates or updates the ServiceMonitor if it already exists.
func createOrUpdateServiceMonitor(ctx context.Context, mClient *monclientv1.MonitoringV1Client,
	namespace string, serviceMonitor *monitoring.ServiceMonitor) error {
	_, err := mClient.ServiceMonitors(namespace).Create(ctx, serviceMonitor, metav1.CreateOptions{})
	if err != nil && !kerr.IsAlreadyExists(err) {
		return err
	}
	if kerr.IsAlreadyExists(err) {
		currentServiceMonitor, getErr := mClient.ServiceMonitors(namespace).Get(ctx, serviceMonitor.Name,
			metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}
		serviceMonitorCopy := currentServiceMonitor.DeepCopy()
		serviceMonitorCopy.Spec = serviceMonitor.Spec
		if _, updateErr := mClient.ServiceMonitors(namespace).Update(ctx, serviceMonitorCopy,
			metav1.UpdateOptions{}); updateErr != nil {
			return updateErr
		}
	}
	return nil
}

// handleServiceMonitor attempts to create a ServiceMonitor out of service, and updates it to include the controller
// metrics paths.
func handleServiceMonitor(ctx context.Context, cfg *rest.Config, mClient *monclientv1.MonitoringV1Client,
	namespace string, service *v1.Service) error {
	ok, err := ResourceExists(discovery.NewDiscoveryClientForConfigOrDie(cfg),
		"monitoring.coreos.com/v1", "ServiceMonitor")
	if err != nil {
		return err
	}
	if !ok {
		log.Info("Install prometheus-operator in your cluster to create ServiceMonitor objects")
		return nil
	}

	serviceMonitor := generateOperatorServiceMonitor(service, namespace)

	return createOrUpdateServiceMonitor(ctx, mClient, namespace, serviceMonitor)
}

// createNonComplianceAlert tries to create the default PrometheusRule. Returns nil.
func createNonComplianceAlert(ctx context.Context, client *monclientv1.MonitoringV1Client, namespace string) error {
	duration := monitoring.Duration("1s")
	rule := monitoring.Rule{
		Alert: "NonCompliant",
		Expr:  intstr.FromString(`compliance_operator_compliance_state{name=~".+"} > 0`),
		For:   &duration,
		Labels: map[string]string{
			"severity": "warning",
		},
		Annotations: map[string]string{
			"summary":     "The cluster is out-of-compliance",
			"description": "The compliance suite {{ $labels.name }} returned as NON-COMPLIANT, ERROR, or INCONSISTENT",
		},
	}
	_, createErr := client.PrometheusRules(namespace).Create(ctx, &monitoring.PrometheusRule{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      alertName,
		},
		Spec: monitoring.PrometheusRuleSpec{
			Groups: []monitoring.RuleGroup{
				{
					Name: "compliance",
					Rules: []monitoring.Rule{
						rule,
					},
				},
			},
		},
	}, metav1.CreateOptions{})
	if createErr != nil && !kerr.IsAlreadyExists(createErr) {
		setupLog.Info("could not create prometheus rule for alert", createErr)
	}
	return nil
}
