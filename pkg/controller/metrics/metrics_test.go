/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package metrics

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/metrics/metricsfakes"
)

var errTest = errors.New("")

func TestRegisterMetrics(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		prepare   func(*metricsfakes.FakeImpl)
		shouldErr bool
	}{
		{ // success
			prepare: func(*metricsfakes.FakeImpl) {},
		},
		{ // error Register fails
			prepare: func(mock *metricsfakes.FakeImpl) {
				mock.RegisterReturns(errTest)
			},
			shouldErr: true,
		},
	} {
		mock := &metricsfakes.FakeImpl{}
		tc.prepare(mock)

		sut := New()
		sut.impl = mock

		err := sut.Register()

		if tc.shouldErr {
			require.NotNil(t, err)
		} else {
			require.Nil(t, err)
		}
	}
}

func TestComplianceOperatorMetrics(t *testing.T) {
	t.Parallel()

	getMetricValue := func(col prometheus.Collector) int {
		c := make(chan prometheus.Metric, 1)
		col.Collect(c)
		m := dto.Metric{}
		err := (<-c).Write(&m)
		require.Nil(t, err)
		if m.Counter == nil {
			return int(*m.Gauge.Value)
		}
		return int(*m.Counter.Value)
	}

	for _, tc := range []struct {
		when func(m *Metrics)
		then func(m *Metrics)
	}{
		{ // single active
			when: func(m *Metrics) {
				m.IncComplianceScanStatus("foo", v1alpha1.ComplianceScanStatus{
					Result: "bar",
					Phase:  "baz",
				})
			},
			then: func(m *Metrics) {
				ctr, err := m.metrics.metricComplianceScanStatus.GetMetricWith(prometheus.Labels{metricLabelScanName: "foo",
					metricLabelScanResult: "bar",
					metricLabelScanPhase:  "baz",
				})
				require.Nil(t, err)
				require.Equal(t, 1, getMetricValue(ctr))
			},
		},
		{ // gauge compliant
			when: func(m *Metrics) {
				m.SetComplianceStateInCompliance("cstate")
			},
			then: func(m *Metrics) {
				ctr, err := m.metrics.metricComplianceStateGauge.GetMetricWith(prometheus.Labels{metricLabelSuiteName: "cstate"})
				require.Nil(t, err)
				require.Equal(t, METRIC_STATE_COMPLIANT, getMetricValue(ctr))
			},
		},
		{ // gauge non-compliant
			when: func(m *Metrics) {
				m.SetComplianceStateOutOfCompliance("cstate")
			},
			then: func(m *Metrics) {
				ctr, err := m.metrics.metricComplianceStateGauge.GetMetricWith(prometheus.Labels{metricLabelSuiteName: "cstate"})
				require.Nil(t, err)
				require.Equal(t, METRIC_STATE_NON_COMPLIANT, getMetricValue(ctr))
			},
		},
		{ // gauge error
			when: func(m *Metrics) {
				m.SetComplianceStateError("cstate-err")
			},
			then: func(m *Metrics) {
				ctr, err := m.metrics.metricComplianceStateGauge.GetMetricWith(prometheus.Labels{metricLabelSuiteName: "cstate-err"})
				require.Nil(t, err)
				require.Equal(t, METRIC_STATE_ERROR, getMetricValue(ctr))
			},
		},
		{ // gauge inconsistent
			when: func(m *Metrics) {
				m.SetComplianceStateInconsistent("cstate-inc")
			},
			then: func(m *Metrics) {
				ctr, err := m.metrics.metricComplianceStateGauge.GetMetricWith(prometheus.Labels{metricLabelSuiteName: "cstate-inc"})
				require.Nil(t, err)
				require.Equal(t, METRIC_STATE_INCONSISTENT, getMetricValue(ctr))
			},
		},
		{ // remediation status counter
			when: func(m *Metrics) {
				m.IncComplianceRemediationStatus("rem", v1alpha1.ComplianceRemediationStatus{ApplicationState: v1alpha1.RemediationApplied})
			},
			then: func(m *Metrics) {
				ctr, err := m.metrics.metricComplianceRemediationStatus.GetMetricWith(prometheus.Labels{
					metricLabelRemediationName:  "rem",
					metricLabelRemediationState: string(v1alpha1.RemediationApplied),
				})
				require.Nil(t, err)
				require.Equal(t, 1, getMetricValue(ctr))
			},
		},
		{ // scan status with error message increments error counter
			when: func(m *Metrics) {
				m.IncComplianceScanStatus("errorscan", v1alpha1.ComplianceScanStatus{
					Result:       "ERROR",
					Phase:        "DONE",
					ErrorMessage: "something went wrong",
				})
			},
			then: func(m *Metrics) {
				ctr, err := m.metrics.metricComplianceScanError.GetMetricWith(prometheus.Labels{metricLabelScanName: "errorscan"})
				require.Nil(t, err)
				require.Equal(t, 1, getMetricValue(ctr))
			},
		},
		{ // gauge series deleted
			when: func(m *Metrics) {
				m.SetComplianceStateError("cstate-del")
				m.DeleteComplianceStateMetric("cstate-del")
			},
			then: func(m *Metrics) {
				// GetMetricWith would silently re-create the deleted series at 0,
				// so assert the vector is empty instead
				c := make(chan prometheus.Metric, 1)
				m.metrics.metricComplianceStateGauge.Collect(c)
				require.Equal(t, 0, len(c))
			},
		},
	} {
		mock := &metricsfakes.FakeImpl{}
		sut := New()
		sut.impl = mock

		tc.when(sut)
		tc.then(sut)
	}
}

func TestWaitForServingCert(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	origCert, origKey := servingCertFile, servingKeyFile
	servingCertFile, servingKeyFile = certFile, keyFile
	defer func() { servingCertFile, servingKeyFile = origCert, origKey }()

	m := New()

	// Times out while the cert and key are missing.
	err := m.waitForServingCert(context.Background(), 5*time.Millisecond, 50*time.Millisecond)
	require.Error(t, err)

	// Recovers when the cert is minted late, as service-ca does on a
	// fresh deployment.
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = os.WriteFile(certFile, []byte("cert"), 0o600)
		_ = os.WriteFile(keyFile, []byte("key"), 0o600)
	}()
	err = m.waitForServingCert(context.Background(), 5*time.Millisecond, 2*time.Second)
	require.NoError(t, err)

	// Honors context cancellation instead of waiting out the timeout.
	require.NoError(t, os.Remove(certFile))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = m.waitForServingCert(ctx, 5*time.Millisecond, time.Minute)
	require.Error(t, err)
}
