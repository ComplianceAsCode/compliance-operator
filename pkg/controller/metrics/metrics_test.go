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
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	configv1 "github.com/openshift/api/config/v1"

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

func TestSetTLSProfileSpec(t *testing.T) {
	t.Parallel()

	sut := New()
	require.Nil(t, sut.tlsProfileSpec)

	profile := configv1.TLSProfileSpec{
		Ciphers:       configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers,
		MinTLSVersion: configv1.VersionTLS12,
		Groups:        []configv1.TLSGroup{configv1.TLSGroupSecP256r1},
	}
	sut.SetTLSProfileSpec(profile)

	require.NotNil(t, sut.tlsProfileSpec)
	require.Equal(t, configv1.VersionTLS12, sut.tlsProfileSpec.MinTLSVersion)
	require.Equal(t, profile.Ciphers, sut.tlsProfileSpec.Ciphers)
	require.Equal(t, profile.Groups, sut.tlsProfileSpec.Groups)
}

func TestServerTLSGroups(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		groups      []configv1.TLSGroup
		noProfile   bool
		minVersion  configv1.TLSProtocolVersion
		wantCurves  []tls.CurveID
		unsupported string
	}{
		"NIST groups exclude X25519 and preserve order": {
			groups: []configv1.TLSGroup{
				configv1.TLSGroupSecP384r1, configv1.TLSGroupSecP256r1, configv1.TLSGroupSecP521r1,
			},
			wantCurves: []tls.CurveID{tls.CurveP384, tls.CurveP256, tls.CurveP521},
		},
		"TLS 1.3 propagates hybrid groups": {
			groups:     []configv1.TLSGroup{configv1.TLSGroupX25519MLKEM768},
			minVersion: configv1.VersionTLS13,
			wantCurves: []tls.CurveID{tls.X25519MLKEM768},
		},
		"unsupported groups are skipped": {
			groups:      []configv1.TLSGroup{"unknown-group", configv1.TLSGroupSecP256r1},
			wantCurves:  []tls.CurveID{tls.CurveP256},
			unsupported: "unknown-group",
		},
		"all unsupported groups leave Go defaults": {
			groups:      []configv1.TLSGroup{"unknown-group"},
			unsupported: "unknown-group",
		},
		"Go 1.26 hybrid groups are skipped and logged": {
			groups: []configv1.TLSGroup{
				configv1.TLSGroupSecP256r1MLKEM768,
				configv1.TLSGroupSecP256r1,
			},
			wantCurves:  []tls.CurveID{tls.CurveP256},
			unsupported: string(configv1.TLSGroupSecP256r1MLKEM768),
		},
		"unset groups leave Go defaults": {},
		"empty groups leave Go defaults": {groups: []configv1.TLSGroup{}},
		"no profile leaves Go defaults":  {noProfile: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sut := New()
			var logs strings.Builder
			sut.log = funcr.New(func(_, message string) {
				logs.WriteString(message)
			}, funcr.Options{})
			minVersion := tc.minVersion
			if minVersion == "" {
				minVersion = configv1.VersionTLS12
			}
			if !tc.noProfile {
				sut.SetTLSProfileSpec(configv1.TLSProfileSpec{
					Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
					MinTLSVersion: minVersion,
					Groups:        tc.groups,
				})
			}

			c := sut.serverTLSConfig()
			require.Equal(t, tc.wantCurves, c.CurvePreferences)
			require.Equal(t, []string{"http/1.1"}, c.NextProtos)
			if tc.unsupported != "" {
				require.Contains(t, logs.String(), "ciphers or groups unsupported by Go")
				require.Contains(t, logs.String(), tc.unsupported)
			}
			if minVersion == configv1.VersionTLS13 {
				require.Equal(t, uint16(tls.VersionTLS13), c.MinVersion)
			} else {
				require.Equal(t, uint16(tls.VersionTLS12), c.MinVersion)
				require.NotEmpty(t, c.CipherSuites)
			}
		})
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
		{ // delete compliance state metric
			when: func(m *Metrics) {
				m.SetComplianceStateInCompliance("to-delete")
				m.DeleteComplianceStateMetric("to-delete")
			},
			then: func(m *Metrics) {
				collected := make(chan prometheus.Metric, 10)
				m.metrics.metricComplianceStateGauge.Collect(collected)
				close(collected)
				for metric := range collected {
					dm := dto.Metric{}
					require.Nil(t, metric.Write(&dm))
					for _, lp := range dm.GetLabel() {
						require.NotEqual(t, "to-delete", lp.GetValue())
					}
				}
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
