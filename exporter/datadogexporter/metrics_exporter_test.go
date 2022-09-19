// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package datadogexporter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/DataDog/agent-payload/v5/gogen"
	"github.com/DataDog/datadog-agent/pkg/otlp/model/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/confignet"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	conventions "go.opentelemetry.io/collector/semconv/v1.6.1"
	"gopkg.in/zorkian/go-datadog-api.v2"

	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/datadogexporter/internal/metadata"
	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/datadogexporter/internal/testutils"
)

func TestNewExporter(t *testing.T) {
	server := testutils.DatadogServerMock()
	defer server.Close()

	cfg := &Config{
		API: APIConfig{
			Key: "ddog_32_characters_long_api_key1",
		},
		Metrics: MetricsConfig{
			TCPAddr: confignet.TCPAddr{
				Endpoint: server.URL,
			},
			DeltaTTL: 3600,
			HistConfig: HistogramConfig{
				Mode:         HistogramModeDistributions,
				SendCountSum: false,
			},
			SumConfig: SumConfig{
				CumulativeMonotonicMode: CumulativeMonotonicSumModeToDelta,
			},
		},
	}
	params := componenttest.NewNopExporterCreateSettings()
	f := NewFactory()

	// The client should have been created correctly
	exp, err := f.CreateMetricsExporter(context.Background(), params, cfg)
	require.NoError(t, err)
	assert.NotNil(t, exp)
	err = exp.ConsumeMetrics(context.Background(), testutils.TestMetrics.Clone())
	require.NoError(t, err)
	assert.Equal(t, len(server.MetadataChan), 0)

	cfg.HostMetadata.Enabled = true
	cfg.HostMetadata.HostnameSource = HostnameSourceFirstResource
	err = exp.ConsumeMetrics(context.Background(), testutils.TestMetrics.Clone())
	require.NoError(t, err)
	body := <-server.MetadataChan
	var recvMetadata metadata.HostMetadata
	err = json.Unmarshal(body, &recvMetadata)
	require.NoError(t, err)
	assert.Equal(t, recvMetadata.InternalHostname, "custom-hostname")
}

func Test_metricsExporter_PushMetricsData(t *testing.T) {
	attrs := map[string]string{
		conventions.AttributeDeploymentEnvironment: "dev",
		"custom_attribute":                         "custom_value",
	}
	tests := []struct {
		metrics               pmetric.Metrics
		source                source.Source
		hostTags              []string
		histogramMode         HistogramMode
		expectedSeries        map[string]interface{}
		expectedSketchPayload *gogen.SketchPayload
		expectedErr           error
	}{
		{
			metrics: createTestMetrics(attrs),
			source: source.Source{
				Kind:       source.HostnameKind,
				Identifier: "test-host",
			},
			histogramMode: HistogramModeNoBuckets,
			hostTags:      []string{"key1:value1", "key2:value2"},
			expectedErr:   errors.New("no buckets mode and no send count sum are incompatible"),
		},
		{
			metrics: createTestMetrics(attrs),
			source: source.Source{
				Kind:       source.HostnameKind,
				Identifier: "test-host",
			},
			histogramMode: HistogramModeCounters,
			hostTags:      []string{"key1:value1", "key2:value2"},
			expectedSeries: map[string]interface{}{
				"series": []interface{}{
					map[string]interface{}{
						"metric": "int.gauge",
						"points": []interface{}{[]interface{}{float64(0), float64(222)}},
						"type":   "gauge",
						"host":   "test-host",
						"tags":   []interface{}{"env:dev"},
					},
					map[string]interface{}{
						"metric": "otel.system.filesystem.utilization",
						"points": []interface{}{[]interface{}{float64(0), float64(333)}},
						"type":   "gauge",
						"host":   "test-host",
						"tags":   []interface{}{"env:dev"},
					},
					map[string]interface{}{
						"metric": "double.histogram.bucket",
						"points": []interface{}{[]interface{}{float64(0), float64(2)}},
						"type":   "count",
						"host":   "test-host",
						"tags":   []interface{}{"lower_bound:-inf", "upper_bound:0", "env:dev"},
					},
					map[string]interface{}{
						"metric": "double.histogram.bucket",
						"points": []interface{}{[]interface{}{float64(0), float64(18)}},
						"type":   "count",
						"host":   "test-host",
						"tags":   []interface{}{"lower_bound:0", "upper_bound:inf", "env:dev"},
					},
					map[string]interface{}{
						"metric": "system.disk.in_use",
						"points": []interface{}{[]interface{}{float64(0), float64(333)}},
						"type":   "gauge",
						"host":   "test-host",
						"tags":   []interface{}{"env:dev"},
					},
					map[string]interface{}{
						"metric": "otel.datadog_exporter.metrics.running",
						"points": []interface{}{[]interface{}{float64(0), float64(1)}},
						"type":   "gauge",
						"host":   "test-host",
						"tags":   []interface{}{"version:latest", "command:otelcol"},
					},
				},
			},
			expectedSketchPayload: nil,
			expectedErr:           nil,
		},
		{
			metrics: createTestMetrics(attrs),
			source: source.Source{
				Kind:       source.HostnameKind,
				Identifier: "test-host",
			},
			histogramMode: HistogramModeDistributions,
			hostTags:      []string{"key1:value1", "key2:value2"},
			expectedSeries: map[string]interface{}{
				"series": []interface{}{
					map[string]interface{}{
						"metric": "int.gauge",
						"points": []interface{}{[]interface{}{float64(0), float64(222)}},
						"type":   "gauge",
						"host":   "test-host",
						"tags":   []interface{}{"env:dev"},
					},
					map[string]interface{}{
						"metric": "otel.system.filesystem.utilization",
						"points": []interface{}{[]interface{}{float64(0), float64(333)}},
						"type":   "gauge",
						"host":   "test-host",
						"tags":   []interface{}{"env:dev"},
					},
					map[string]interface{}{
						"metric": "system.disk.in_use",
						"points": []interface{}{[]interface{}{float64(0), float64(333)}},
						"type":   "gauge",
						"host":   "test-host",
						"tags":   []interface{}{"env:dev"},
					},
					map[string]interface{}{
						"metric": "otel.datadog_exporter.metrics.running",
						"points": []interface{}{[]interface{}{float64(0), float64(1)}},
						"type":   "gauge",
						"host":   "test-host",
						"tags":   []interface{}{"version:latest", "command:otelcol"},
					},
				},
			},
			expectedSketchPayload: &gogen.SketchPayload{
				Sketches: []gogen.SketchPayload_Sketch{
					{
						Metric: "double.histogram",
						Host:   "test-host",
						Tags:   []string{"env:dev"},
						Dogsketches: []gogen.SketchPayload_Sketch_Dogsketch{
							{
								Cnt: 20,
								Avg: 0.3,
								Sum: 6,
								K:   []int32{0},
								N:   []uint32{20},
							},
						},
					},
				},
			},
			expectedErr: nil,
		},
		{
			metrics: createTestMetrics(attrs),
			source: source.Source{
				Kind:       source.AWSECSFargateKind,
				Identifier: "task_arn",
			},
			histogramMode: HistogramModeCounters,
			hostTags:      []string{"key1:value1", "key2:value2"},
			expectedSeries: map[string]interface{}{
				"series": []interface{}{
					map[string]interface{}{
						"metric": "int.gauge",
						"points": []interface{}{[]interface{}{float64(0), float64(222)}},
						"type":   "gauge",
						"host":   "test-host",
						"tags":   []interface{}{"env:dev", "key1:value1", "key2:value2"},
					},
					map[string]interface{}{
						"metric": "otel.system.filesystem.utilization",
						"points": []interface{}{[]interface{}{float64(0), float64(333)}},
						"type":   "gauge",
						"host":   "test-host",
						"tags":   []interface{}{"env:dev", "key1:value1", "key2:value2"},
					},
					map[string]interface{}{
						"metric": "double.histogram.bucket",
						"points": []interface{}{[]interface{}{float64(0), float64(2)}},
						"type":   "count",
						"host":   "test-host",
						"tags":   []interface{}{"lower_bound:-inf", "upper_bound:0", "env:dev", "key1:value1", "key2:value2"},
					},
					map[string]interface{}{
						"metric": "double.histogram.bucket",
						"points": []interface{}{[]interface{}{float64(0), float64(18)}},
						"type":   "count",
						"host":   "test-host",
						"tags":   []interface{}{"lower_bound:0", "upper_bound:inf", "env:dev", "key1:value1", "key2:value2"},
					},
					map[string]interface{}{
						"metric": "system.disk.in_use",
						"points": []interface{}{[]interface{}{float64(0), float64(333)}},
						"type":   "gauge",
						"host":   "test-host",
						"tags":   []interface{}{"env:dev", "key1:value1", "key2:value2"},
					},
					map[string]interface{}{
						"metric": "otel.datadog_exporter.metrics.running",
						"points": []interface{}{[]interface{}{float64(0), float64(1)}},
						"type":   "gauge",
						"host":   "test-host",
						"tags":   []interface{}{"version:latest", "command:otelcol", "key1:value1", "key2:value2"},
					},
				},
			},
			expectedSketchPayload: nil,
			expectedErr:           nil,
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("kind=%s,histgramMode=%s", tt.source.Kind, tt.histogramMode), func(t *testing.T) {
			seriesRecorder := &testutils.HTTPRequestRecorder{Pattern: "/api/v1/series"}
			sketchRecorder := &testutils.HTTPRequestRecorder{Pattern: "/api/beta/sketches"}
			server := testutils.DatadogServerMock(
				seriesRecorder.HandlerFunc,
				sketchRecorder.HandlerFunc,
			)
			defer server.Close()

			var once sync.Once
			exp, err := newMetricsExporter(
				context.Background(),
				componenttest.NewNopExporterCreateSettings(),
				newTestConfig(t, server.URL, tt.hostTags, tt.histogramMode),
				&once,
				&testutils.MockSourceProvider{Src: tt.source},
			)
			if tt.expectedErr == nil {
				assert.NoError(t, err, "unexpected error")
			} else {
				assert.Equal(t, tt.expectedErr, err, "expected error doesn't match")
				return
			}
			exp.getPushTime = func() uint64 { return 0 }
			err = exp.PushMetricsData(context.Background(), tt.metrics)
			if tt.expectedErr == nil {
				assert.NoError(t, err, "unexpected error")
			} else {
				assert.Equal(t, tt.expectedErr, err, "expected error doesn't match")
				return
			}
			if len(tt.expectedSeries) == 0 {
				assert.Nil(t, seriesRecorder.ByteBody)
			} else {
				assert.Equal(t, "gzip", seriesRecorder.Header.Get("Accept-Encoding"))
				assert.Equal(t, "application/json", seriesRecorder.Header.Get("Content-Type"))
				assert.Equal(t, "otelcol/latest", seriesRecorder.Header.Get("User-Agent"))
				assert.NoError(t, err)
				var actual map[string]interface{}
				assert.NoError(t, json.Unmarshal(seriesRecorder.ByteBody, &actual))
				assert.Equal(t, tt.expectedSeries, actual)
			}
			if tt.expectedSketchPayload == nil {
				assert.Nil(t, sketchRecorder.ByteBody)
			} else {
				assert.Equal(t, "gzip", sketchRecorder.Header.Get("Accept-Encoding"))
				assert.Equal(t, "application/x-protobuf", sketchRecorder.Header.Get("Content-Type"))
				assert.Equal(t, "otelcol/latest", sketchRecorder.Header.Get("User-Agent"))
				expected, err := tt.expectedSketchPayload.Marshal()
				assert.NoError(t, err)
				assert.Equal(t, expected, sketchRecorder.ByteBody)
			}
		})
	}
}

func TestPrepareSystemMetrics(t *testing.T) {
	var once sync.Once
	cfg := NewFactory().CreateDefaultConfig().(*Config)
	exp, err := newMetricsExporter(
		context.Background(),
		componenttest.NewNopExporterCreateSettings(),
		cfg,
		&once,
		&testutils.MockSourceProvider{Src: source.Source{
			Kind:       source.AWSECSFargateKind,
			Identifier: "task_arn",
		}},
	)
	require.NoError(t, err)
	sptr := func(s string) *string { return &s }
	dptr := func(d int) *int { return &d }
	ms := []datadog.Metric{
		{Metric: sptr("system.something")},
		{Metric: sptr("process.something")},
		{Metric: sptr("process.cpu.time")},
		{Metric: sptr("system.memory.usage")},
		{Metric: sptr("system.filesystem.utilization")},
		{Metric: sptr("system.network.io")},
		{Metric: sptr("system.memory.usage")},
		{Metric: sptr("system.cpu.utilization")},
		{Metric: sptr("system.cpu.load_average.1m")},
		{Metric: sptr("system.cpu.load_average.5m")},
		{Metric: sptr("system.cpu.load_average.15m")},
		{Metric: sptr("processes.cpu.time")},
		{Metric: sptr("systemd.metric.name")},
		{Metric: sptr("random.metric.name")},
		{Metric: sptr("system.disk.in_use")},
		{Metric: sptr("system.net.bytes_sent")},
		{Metric: sptr("system.net.bytes_rcvd")},
		{Metric: sptr("system.mem.usable")},
		{Metric: sptr("system.mem.total")},
		{Metric: sptr("system.cpu.stolen")},
		{Metric: sptr("system.cpu.iowait")},
		{Metric: sptr("system.cpu.system")},
		{Metric: sptr("system.cpu.user")},
		{Metric: sptr("system.cpu.idle")},
		{Metric: sptr("system.swap.free")},
		{Metric: sptr("system.swap.used")},
		{Metric: sptr("system.load.15")},
		{Metric: sptr("system.load.5")},
		{Metric: sptr("system.load.1")},
	}
	exp.prepareSystemMetrics(ms)
	require.EqualValues(t, ms, []datadog.Metric{
		{Metric: sptr("otel.system.something")},
		{Metric: sptr("otel.process.something")},
		{Metric: sptr("otel.process.cpu.time")},
		{Metric: sptr("otel.system.memory.usage")},
		{Metric: sptr("otel.system.filesystem.utilization")},
		{Metric: sptr("otel.system.network.io")},
		{Metric: sptr("otel.system.memory.usage")},
		{Metric: sptr("otel.system.cpu.utilization")},
		{Metric: sptr("otel.system.cpu.load_average.1m")},
		{Metric: sptr("otel.system.cpu.load_average.5m")},
		{Metric: sptr("otel.system.cpu.load_average.15m")},
		{Metric: sptr("processes.cpu.time")},
		{Metric: sptr("systemd.metric.name")},
		{Metric: sptr("random.metric.name")},
		{Metric: sptr("system.disk.in_use")},
		{Metric: sptr("system.net.bytes_sent"), Type: sptr("gauge"), Interval: dptr(1)},
		{Metric: sptr("system.net.bytes_rcvd"), Type: sptr("gauge"), Interval: dptr(1)},
		{Metric: sptr("system.mem.usable"), Interval: dptr(1)},
		{Metric: sptr("system.mem.total"), Interval: dptr(1)},
		{Metric: sptr("system.cpu.stolen")},
		{Metric: sptr("system.cpu.iowait")},
		{Metric: sptr("system.cpu.system"), Interval: dptr(1)},
		{Metric: sptr("system.cpu.user"), Interval: dptr(1)},
		{Metric: sptr("system.cpu.idle"), Interval: dptr(1)},
		{Metric: sptr("system.swap.free"), Interval: dptr(1)},
		{Metric: sptr("system.swap.used"), Interval: dptr(1)},
		{Metric: sptr("system.load.15"), Interval: dptr(1)},
		{Metric: sptr("system.load.5"), Interval: dptr(1)},
		{Metric: sptr("system.load.1"), Interval: dptr(1)},
	})
}

func createTestMetrics(additionalAttributes map[string]string) pmetric.Metrics {
	const (
		host    = "test-host"
		name    = "test-metrics"
		version = "v0.0.1"
	)
	md := pmetric.NewMetrics()
	rms := md.ResourceMetrics()
	rm := rms.AppendEmpty()

	attrs := rm.Resource().Attributes()
	attrs.PutString("datadog.host.name", host)
	for attr, val := range additionalAttributes {
		attrs.PutString(attr, val)
	}
	ilms := rm.ScopeMetrics()

	ilm := ilms.AppendEmpty()
	ilm.Scope().SetName(name)
	ilm.Scope().SetVersion(version)
	metricsArray := ilm.Metrics()
	metricsArray.AppendEmpty() // first one is TypeNone to test that it's ignored

	// IntGauge
	met := metricsArray.AppendEmpty()
	met.SetName("int.gauge")
	dpsInt := met.SetEmptyGauge().DataPoints()
	dpInt := dpsInt.AppendEmpty()
	dpInt.SetTimestamp(seconds(0))
	dpInt.SetIntVal(222)

	// host metric
	met = metricsArray.AppendEmpty()
	met.SetName("system.filesystem.utilization")
	dpsInt = met.SetEmptyGauge().DataPoints()
	dpInt = dpsInt.AppendEmpty()
	dpInt.SetTimestamp(seconds(0))
	dpInt.SetIntVal(333)

	// Histogram (delta)
	met = metricsArray.AppendEmpty()
	met.SetName("double.histogram")
	met.SetEmptyHistogram().SetAggregationTemporality(pmetric.MetricAggregationTemporalityDelta)
	dpsDoubleHist := met.Histogram().DataPoints()
	dpDoubleHist := dpsDoubleHist.AppendEmpty()
	dpDoubleHist.SetCount(20)
	dpDoubleHist.SetSum(6)
	dpDoubleHist.BucketCounts().FromRaw([]uint64{2, 18})
	dpDoubleHist.ExplicitBounds().FromRaw([]float64{0})
	dpDoubleHist.SetTimestamp(seconds(0))

	return md
}

func seconds(i int) pcommon.Timestamp {
	return pcommon.NewTimestampFromTime(time.Unix(int64(i), 0))
}

func newTestConfig(t *testing.T, endpoint string, hostTags []string, histogramMode HistogramMode) *Config {
	t.Helper()
	return &Config{
		HostMetadata: HostMetadataConfig{
			Tags: hostTags,
		},
		Metrics: MetricsConfig{
			TCPAddr: confignet.TCPAddr{
				Endpoint: endpoint,
			},
			HistConfig: HistogramConfig{
				Mode: histogramMode,
			},
			// Set values to avoid errors. No particular intention in value selection.
			DeltaTTL: 3600,
			SumConfig: SumConfig{
				CumulativeMonotonicMode: CumulativeMonotonicSumModeRawValue,
			},
		},
	}
}
