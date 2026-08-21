package metrics

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-logr/logr"
	libgocrypto "github.com/openshift/library-go/pkg/crypto"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/apimachinery/pkg/util/wait"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
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

// The metrics serving certificate is mounted from the secret minted by the
// OpenShift service-ca operator. Package-level vars so tests can redirect
// them to a temporary directory.
var (
	servingCertFile = "/var/run/secrets/serving-cert/tls.crt"
	servingKeyFile  = "/var/run/secrets/serving-cert/tls.key"
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

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}
	tlsConfig = libgocrypto.SecureTLSConfig(tlsConfig)
	server := &http.Server{
		Addr:      MetricsAddrListen,
		TLSConfig: tlsConfig,
	}

	// The serving cert is minted asynchronously by the service-ca operator
	// once the metrics Service exists, and this runnable can win that race
	// on a fresh deployment. A one-shot ListenAndServeTLS would then fail
	// and leave the endpoint dead for the life of the pod (the error below
	// is deliberately not propagated), so wait for the files to show up.
	if err := m.waitForServingCert(ctx, 5*time.Second, 5*time.Minute); err != nil {
		// unhandled on purpose, we don't want to exit the operator.
		m.log.Error(err, "Metrics service failed: serving cert never became available")
		return nil
	}

	err := server.ListenAndServeTLS(servingCertFile, servingKeyFile)
	if err != nil {
		// unhandled on purpose, we don't want to exit the operator.
		m.log.Error(err, "Metrics service failed")
	}
	return nil
}

// waitForServingCert polls until both the serving certificate and key exist,
// the context is cancelled, or the timeout expires.
func (m *Metrics) waitForServingCert(ctx context.Context, interval, timeout time.Duration) error {
	return wait.PollUntilContextTimeout(ctx, interval, timeout, true, func(context.Context) (bool, error) {
		for _, f := range []string{servingCertFile, servingKeyFile} {
			if _, err := os.Stat(f); err != nil {
				m.log.Info("Waiting for the metrics serving cert", "file", f)
				return false, nil
			}
		}
		return true, nil
	})
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

// DeleteComplianceStateMetric removes the compliance_state series for the named
// suite. Called when a ComplianceSuite is deleted so its gauge no longer reports
// a stale value.
func (m *Metrics) DeleteComplianceStateMetric(name string) {
	m.metrics.metricComplianceStateGauge.DeleteLabelValues(name)
}
