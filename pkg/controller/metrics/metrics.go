package metrics

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
)

const (
	metricNamespace = "compliance_operator"

	metricNameComplianceScanStatus        = "compliance_scan_status_total"
	metricNameComplianceScanError         = "compliance_scan_error_total"
	metricNameComplianceRemediationStatus = "compliance_remediation_status_total"
	metricNameComplianceStateGauge        = "compliance_state"

	metricLabelScanResult       = "result"
	metricLabelScanName         = "name"
	metricLabelSuiteName        = "name"
	metricLabelScanPhase        = "phase"
	metricLabelScanError        = "error"
	metricLabelRemediationName  = "name"
	metricLabelRemediationState = "state"

	HandlerPath                  = "/metrics-co"
	ControllerMetricsServiceName = "metrics-co"
	ControllerMetricsPort        = 8585
	MetricsAddrListen            = ":8585"
)

const (
	METRIC_STATE_COMPLIANT = iota
	METRIC_STATE_NON_COMPLIANT
	METRIC_STATE_INCONSISTENT
	METRIC_STATE_ERROR
)

// Metrics is the main structure of this package.
type Metrics struct {
	impl    impl
	log     logr.Logger
	metrics *ControllerMetrics
}

type ControllerMetrics struct {
	metricComplianceScanError         *prometheus.CounterVec
	metricComplianceScanStatus        *prometheus.CounterVec
	metricComplianceRemediationStatus *prometheus.CounterVec
	metricComplianceStateGauge        *prometheus.GaugeVec
}

func DefaultControllerMetrics() *ControllerMetrics {
	return &ControllerMetrics{
		metricComplianceScanError: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameComplianceScanError,
				Namespace: metricNamespace,
				Help:      "A counter for the total number of errors for a particular scan",
			},
			[]string{metricLabelScanName},
		),
		metricComplianceScanStatus: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameComplianceScanStatus,
				Namespace: metricNamespace,
				Help:      "A counter for the total number of updates to the status of a ComplianceScan",
			},
			[]string{
				metricLabelScanName,
				metricLabelScanPhase,
				metricLabelScanResult,
			},
		),
		metricComplianceRemediationStatus: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      metricNameComplianceRemediationStatus,
				Namespace: metricNamespace,
				Help:      "A counter for the total number of updates to the status of a ComplianceRemediation",
			},
			[]string{
				metricLabelRemediationName,
				metricLabelRemediationState,
			},
		),
		metricComplianceStateGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:      metricNameComplianceStateGauge,
				Namespace: metricNamespace,
				Help:      "A gauge for the compliance state of a ComplianceSuite. Set to 0 when COMPLIANT, 1 when NON-COMPLIANT, 2 when INCONSISTENT, and 3 when ERROR",
			},
			[]string{
				metricLabelSuiteName,
			},
		),
	}
}

func NewMetrics(imp impl) *Metrics {
	return &Metrics{
		impl:    imp,
		log:     ctrllog.Log.WithName("metrics"),
		metrics: DefaultControllerMetrics(),
	}
}

// New returns a new default Metrics instance.
func New() *Metrics {
	return NewMetrics(&defaultImpl{})
}

// Register iterates over all available metrics and registers them.
func (m *Metrics) Register() error {
	for name, collector := range map[string]prometheus.Collector{
		metricNameComplianceScanError:         m.metrics.metricComplianceScanError,
		metricNameComplianceScanStatus:        m.metrics.metricComplianceScanStatus,
		metricNameComplianceRemediationStatus: m.metrics.metricComplianceRemediationStatus,
		metricNameComplianceStateGauge:        m.metrics.metricComplianceStateGauge,
	} {
		m.log.Info(fmt.Sprintf("Registering metric: %s", name))
		if err := m.impl.Register(collector); err != nil {
			return errors.Wrapf(err, "register collector for %s metric", name)
		}
	}
	return nil
}

func (m *Metrics) Start(ctx context.Context) error {
	m.log.Info("Starting to serve controller metrics")
	http.Handle(HandlerPath, promhttp.Handler())

	cfg, err := config.GetConfig()
	if err != nil {
		m.log.Error(err, "Failed to get Kubernetes config, using default TLS configuration")
		cfg = &rest.Config{}
	}

	// Get TLS configuration from OpenShift APIServer cluster-wide policy
	// Falls back to secure defaults (TLS 1.2) if APIServer config is unavailable
	tlsConfig := utils.GetAPIServerTLSConfigOrDefault(ctx, cfg)
	tlsConfig.NextProtos = []string{"http/1.1"}
	server := &http.Server{
		Addr:      MetricsAddrListen,
		TLSConfig: tlsConfig,
	}

	err = server.ListenAndServeTLS("/var/run/secrets/serving-cert/tls.crt", "/var/run/secrets/serving-cert/tls.key")
	if err != nil {
		// unhandled on purpose, we don't want to exit the operator.
		m.log.Error(err, "Metrics service failed")
	}
	return nil
}

// IncComplianceScanStatus also increments error if necessary
func (m *Metrics) IncComplianceScanStatus(name string, status v1alpha1.ComplianceScanStatus) {
	m.metrics.metricComplianceScanStatus.With(prometheus.Labels{
		metricLabelScanName:   name,
		metricLabelScanPhase:  string(status.Phase),
		metricLabelScanResult: string(status.Result),
	}).Inc()
	if len(status.ErrorMessage) > 0 {
		m.metrics.metricComplianceScanError.With(prometheus.Labels{
			metricLabelScanName: name,
		}).Inc()
	}
}

// IncComplianceRemediationStatus increments the ComplianceRemediation status counter
func (m *Metrics) IncComplianceRemediationStatus(name string, status v1alpha1.ComplianceRemediationStatus) {
	m.metrics.metricComplianceRemediationStatus.With(prometheus.Labels{
		metricLabelRemediationName:  name,
		metricLabelRemediationState: string(status.ApplicationState),
	}).Inc()
}

// SetComplianceStateError sets the compliance_state gauge to 3.
func (m *Metrics) SetComplianceStateError(name string) {
	m.metrics.metricComplianceStateGauge.WithLabelValues(name).Set(METRIC_STATE_ERROR)
}

// SetComplianceStateInconsistent sets the compliance_state gauge to 2.
func (m *Metrics) SetComplianceStateInconsistent(name string) {
	m.metrics.metricComplianceStateGauge.WithLabelValues(name).Set(METRIC_STATE_INCONSISTENT)
}

// SetComplianceStateOutOfCompliance sets the compliance_state gauge to 1.
func (m *Metrics) SetComplianceStateOutOfCompliance(name string) {
	m.metrics.metricComplianceStateGauge.WithLabelValues(name).Set(METRIC_STATE_NON_COMPLIANT)
}

// SetComplianceStateInCompliance sets the compliance_state gauge to 0.
func (m *Metrics) SetComplianceStateInCompliance(name string) {
	m.metrics.metricComplianceStateGauge.WithLabelValues(name).Set(METRIC_STATE_COMPLIANT)
}
