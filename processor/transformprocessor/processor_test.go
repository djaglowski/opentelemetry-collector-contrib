// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transformprocessor

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor/processortest"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/opampcustommessages"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/golden"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/pdatatest/plogtest"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor/internal/common"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor/internal/metadata"
)

func TestFlattenDataDisabledByDefault(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
	oCfg := cfg.(*Config)
	assert.False(t, oCfg.FlattenData)
	assert.NoError(t, oCfg.Validate())
}

func TestFlattenDataRequiresGate(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
	oCfg := cfg.(*Config)
	oCfg.FlattenData = true
	assert.Equal(t, errFlatLogsGateDisabled, oCfg.Validate())
}

func TestProcessLogsWithoutFlatten(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
	oCfg := cfg.(*Config)
	oCfg.LogStatements = []common.ContextStatements{
		{
			Context: "log",
			Statements: []string{
				`set(resource.attributes["host.name"], attributes["host.name"])`,
				`delete_key(attributes, "host.name")`,
			},
		},
	}
	sink := new(consumertest.LogsSink)
	p, err := factory.CreateLogs(context.Background(), processortest.NewNopSettingsWithType(metadata.Type), oCfg, sink)
	require.NoError(t, err)

	input, err := golden.ReadLogs(filepath.Join("testdata", "logs", "input.yaml"))
	require.NoError(t, err)
	expected, err := golden.ReadLogs(filepath.Join("testdata", "logs", "expected-without-flatten.yaml"))
	require.NoError(t, err)

	assert.NoError(t, p.ConsumeLogs(context.Background(), input))

	actual := sink.AllLogs()
	require.Len(t, actual, 1)

	assert.NoError(t, plogtest.CompareLogs(expected, actual[0]))
}

func TestProcessLogsWithFlatten(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
	oCfg := cfg.(*Config)
	oCfg.FlattenData = true
	oCfg.LogStatements = []common.ContextStatements{
		{
			Context: "log",
			Statements: []string{
				`set(resource.attributes["host.name"], attributes["host.name"])`,
				`delete_key(attributes, "host.name")`,
			},
		},
	}
	sink := new(consumertest.LogsSink)
	p, err := factory.CreateLogs(context.Background(), processortest.NewNopSettingsWithType(metadata.Type), oCfg, sink)
	require.NoError(t, err)

	input, err := golden.ReadLogs(filepath.Join("testdata", "logs", "input.yaml"))
	require.NoError(t, err)
	expected, err := golden.ReadLogs(filepath.Join("testdata", "logs", "expected-with-flatten.yaml"))
	require.NoError(t, err)

	assert.NoError(t, p.ConsumeLogs(context.Background(), input))

	actual := sink.AllLogs()
	require.Len(t, actual, 1)

	assert.NoError(t, plogtest.CompareLogs(expected, actual[0]))
}

func BenchmarkLogsWithoutFlatten(b *testing.B) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
	oCfg := cfg.(*Config)
	oCfg.LogStatements = []common.ContextStatements{
		{
			Context: "log",
			Statements: []string{
				`set(resource.attributes["host.name"], attributes["host.name"])`,
				`delete_key(attributes, "host.name")`,
			},
		},
	}
	sink := new(consumertest.LogsSink)
	p, err := factory.CreateLogs(context.Background(), processortest.NewNopSettingsWithType(metadata.Type), oCfg, sink)
	require.NoError(b, err)

	input, err := golden.ReadLogs(filepath.Join("testdata", "logs", "input.yaml"))
	require.NoError(b, err)

	for n := 0; n < b.N; n++ {
		assert.NoError(b, p.ConsumeLogs(context.Background(), input))
	}
}

func BenchmarkLogsWithFlatten(b *testing.B) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
	oCfg := cfg.(*Config)
	oCfg.FlattenData = true
	oCfg.LogStatements = []common.ContextStatements{
		{
			Context: "log",
			Statements: []string{
				`set(resource.attributes["host.name"], attributes["host.name"])`,
				`delete_key(attributes, "host.name")`,
			},
		},
	}
	sink := new(consumertest.LogsSink)
	p, err := factory.CreateLogs(context.Background(), processortest.NewNopSettingsWithType(metadata.Type), oCfg, sink)
	require.NoError(b, err)

	input, err := golden.ReadLogs(filepath.Join("testdata", "logs", "input.yaml"))
	require.NoError(b, err)

	for n := 0; n < b.N; n++ {
		assert.NoError(b, p.ConsumeLogs(context.Background(), input))
	}
}

type mockCustomCapabilityClient struct {
	msgChan   chan *CustomMessage
	protoChan chan *protobufs.CustomMessage
	unreg     func()
	responses []struct {
		Type string
		Body string
	}
	mu sync.Mutex
}

func (m *mockCustomCapabilityClient) Message() <-chan *protobufs.CustomMessage {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.protoChan == nil {
		m.protoChan = make(chan *protobufs.CustomMessage, 10)
		go func() {
			defer close(m.protoChan)
			for msg := range m.msgChan {
				protoMsg := &protobufs.CustomMessage{
					Capability: transformCapability,
					Type:       msg.Type,
					Data:       []byte(msg.Body),
				}
				m.protoChan <- protoMsg
			}
		}()
	}
	return m.protoChan
}

func (m *mockCustomCapabilityClient) MessageChan() <-chan *CustomMessage {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.msgChan == nil {
		m.msgChan = make(chan *CustomMessage, 10)
	}
	return m.msgChan
}

func (m *mockCustomCapabilityClient) Unregister() {
	if m.unreg != nil {
		m.unreg()
	}
	close(m.msgChan)
}

func (m *mockCustomCapabilityClient) SendMessage(typ string, body []byte) (chan struct{}, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses = append(m.responses, struct {
		Type string
		Body string
	}{Type: typ, Body: string(body)})
	ch := make(chan struct{})
	close(ch)
	return ch, nil
}

type mockCustomCapabilityRegistry struct {
	client *mockCustomCapabilityClient
}

func (m *mockCustomCapabilityRegistry) Register(capability string, opts ...opampcustommessages.CustomCapabilityRegisterOption) (opampcustommessages.CustomCapabilityHandler, error) {
	return m.client, nil
}

type mockOpAMPExtension struct {
	registry *mockCustomCapabilityRegistry
}

func (m *mockOpAMPExtension) Register(capability string, opts ...opampcustommessages.CustomCapabilityRegisterOption) (opampcustommessages.CustomCapabilityHandler, error) {
	return m.registry.Register(capability)
}

func (m *mockOpAMPExtension) Start(context.Context, component.Host) error { return nil }
func (m *mockOpAMPExtension) Shutdown(context.Context) error              { return nil }

func TestOpAMPIntegration(t *testing.T) {
	// Create a real logger for debugging
	logCfg := zap.NewDevelopmentConfig()
	logCfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	logger, err := logCfg.Build()
	require.NoError(t, err)
	defer logger.Sync()

	// Create a mock OpAMP extension with pre-initialized channels
	mockClient := &mockCustomCapabilityClient{
		msgChan:   make(chan *CustomMessage, 10),
		protoChan: make(chan *protobufs.CustomMessage, 10),
		unreg: func() {
			logger.Info("Unregister called")
		},
	}

	// Initialize the message forwarding goroutine
	go func() {
		for msg := range mockClient.msgChan {
			logger.Info("Forwarding message",
				zap.String("type", msg.Type),
				zap.String("body", msg.Body))
			protoMsg := &protobufs.CustomMessage{
				Capability: transformCapability,
				Type:       msg.Type,
				Data:       []byte(msg.Body),
			}
			mockClient.protoChan <- protoMsg
		}
	}()

	mockRegistry := &mockCustomCapabilityRegistry{client: mockClient}
	mockExt := &mockOpAMPExtension{registry: mockRegistry}

	// Create a host with the mock extension
	opampID := component.NewIDWithName(component.MustNewType("opamp"), "")
	host := &mockHost{
		extensions: map[component.ID]component.Component{
			opampID: mockExt,
		},
	}

	// Create processor config with OpAMP enabled
	cfg := &Config{
		OpAMP: &opampID,
		TraceStatements: []common.ContextStatements{
			{
				Context: "span",
				Statements: []string{
					`set(attributes["original"], "value")`,
				},
				ErrorMode: "ignore",
			},
		},
	}

	// Create the processor
	settings := componenttest.NewNopTelemetrySettings()
	settings.Logger = logger
	processor, err := newProcessor(settings, cfg)
	require.NoError(t, err)

	// Start the processor
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = processor.Start(ctx, host)
	require.NoError(t, err)

	// Create test trace data
	traces := ptrace.NewTraces()
	span := traces.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetName("test")

	// Process traces with original config
	processed, err := processor.ProcessTraces(ctx, traces)
	require.NoError(t, err)
	attrs := processed.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
	origVal, ok := attrs.Get("original")
	require.True(t, ok)
	assert.Equal(t, "value", origVal.Str())

	// Send valid config via OpAMP
	type contextStatements struct {
		Context     string   `json:"context"`
		Statements  []string `json:"statements"`
		ErrorMode   string   `json:"error_mode"`
		SharedCache bool     `json:"shared_cache"`
	}
	newStatements := struct {
		TraceStatements []contextStatements `json:"trace_statements"`
	}{
		TraceStatements: []contextStatements{
			{
				Context: "span",
				Statements: []string{
					`set(span.attributes["updated"], "new-value")`,
					`delete_key(span.attributes, "original")`,
				},
				ErrorMode: "ignore",
			},
		},
	}
	body, err := json.Marshal(newStatements)
	require.NoError(t, err)

	logger.Info("Sending new statements", zap.String("body", string(body)))

	// Send the message
	mockClient.msgChan <- &CustomMessage{
		Type: transformMsgType,
		Body: string(body),
	}

	// Wait for the processor to process the message
	time.Sleep(100 * time.Millisecond)

	// Verify the changes took effect
	processed, err = processor.ProcessTraces(ctx, traces)
	require.NoError(t, err)
	attrs = processed.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()

	// Original attribute should be gone
	_, hasOriginal := attrs.Get("original")
	require.False(t, hasOriginal, "original attribute should have been deleted")

	// New attribute should be present with correct value
	updatedVal, hasUpdated := attrs.Get("updated")
	require.True(t, hasUpdated, "updated attribute should be present")
	assert.Equal(t, "new-value", updatedVal.Str())

	// Shutdown should unregister from OpAMP
	err = processor.Shutdown(ctx)
	require.NoError(t, err)
}

type mockHost struct {
	extensions map[component.ID]component.Component
	sync.Mutex
}

func (m *mockHost) GetExtensions() map[component.ID]component.Component {
	m.Lock()
	defer m.Unlock()
	return m.extensions
}

func (m *mockHost) GetFactory(_ component.Kind, _ component.Type) component.Factory {
	return nil
}

func (m *mockHost) GetExporters() map[component.ID]component.Component {
	return nil
}
