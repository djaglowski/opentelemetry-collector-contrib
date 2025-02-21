// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transformprocessor

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/opampcustommessages"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor/internal/common"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor/internal/logs"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor/internal/metrics"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor/internal/traces"
	"gopkg.in/yaml.v3"
)

const (
	transformCapability = "transform"
	transformMsgType    = "statements"
)

type transformProcessor struct {
	logger   *zap.Logger
	cfg      *Config
	settings component.TelemetrySettings

	opampClient interface {
		MessageChan() <-chan *CustomMessage
		Unregister()
		SendMessage(string, []byte) (chan struct{}, error)
	}
	opampMux sync.RWMutex

	logsProcessor    *logs.Processor
	tracesProcessor  *traces.Processor
	metricsProcessor *metrics.Processor
}

// CustomMessage represents a message received from OpAMP
type CustomMessage struct {
	Type string
	Body string
}

// ValidationError represents a validation error response
type ValidationError struct {
	Error string `json:"error"`
	Type  string `json:"type"`
}

func newProcessor(settings component.TelemetrySettings, cfg *Config) (*transformProcessor, error) {
	p := &transformProcessor{
		logger:   settings.Logger,
		cfg:      cfg,
		settings: settings,
	}

	var err error
	if len(cfg.LogStatements) > 0 {
		p.logsProcessor, err = logs.NewProcessor(cfg.LogStatements, cfg.ErrorMode, cfg.FlattenData, settings)
		if err != nil {
			return nil, fmt.Errorf("failed to create logs processor: %w", err)
		}
	}

	if len(cfg.TraceStatements) > 0 {
		p.tracesProcessor, err = traces.NewProcessor(cfg.TraceStatements, cfg.ErrorMode, settings)
		if err != nil {
			return nil, fmt.Errorf("failed to create traces processor: %w", err)
		}
	}

	if len(cfg.MetricStatements) > 0 {
		p.metricsProcessor, err = metrics.NewProcessor(cfg.MetricStatements, cfg.ErrorMode, settings)
		if err != nil {
			return nil, fmt.Errorf("failed to create metrics processor: %w", err)
		}
	}

	return p, nil
}

func (p *transformProcessor) Start(ctx context.Context, host component.Host) error {
	if p.cfg.OpAMP == nil {
		return nil
	}

	opampID := component.NewIDWithName(component.MustNewType("opamp"), "")
	ext, ok := host.GetExtensions()[opampID]
	if !ok {
		return fmt.Errorf("opamp extension not found")
	}

	registry, ok := ext.(opampcustommessages.CustomCapabilityRegistry)
	if !ok {
		return fmt.Errorf("extension 'opamp' does not support custom capabilities")
	}

	// Register our custom capability
	handler, err := registry.Register(transformCapability)
	if err != nil {
		return fmt.Errorf("failed to register transform capability: %w", err)
	}

	// Create the adapter with pre-initialized channels
	adapter := &customMessageAdapter{
		msgChan: make(chan *CustomMessage, 10),
		handler: handler,
		done:    make(chan struct{}),
	}

	// Start message forwarding in a goroutine
	go func() {
		defer close(adapter.msgChan)
		for {
			select {
			case <-ctx.Done():
				return
			case <-adapter.done:
				return
			case msg := <-handler.Message():
				p.logger.Debug("Received message from handler",
					zap.String("type", msg.Type),
					zap.String("data", string(msg.Data)))
				select {
				case adapter.msgChan <- &CustomMessage{
					Type: msg.Type,
					Body: string(msg.Data),
				}:
				case <-ctx.Done():
					return
				case <-adapter.done:
					return
				}
			}
		}
	}()

	p.opampClient = adapter

	// Start a goroutine to handle incoming messages
	go p.handleOpAMPMessages(ctx)

	return nil
}

func (p *transformProcessor) handleOpAMPMessages(ctx context.Context) {
	p.logger.Info("Starting OpAMP message handler")
	for {
		select {
		case <-ctx.Done():
			p.logger.Debug("Context done, exiting handleOpAMPMessages")
			return
		case msg := <-p.opampClient.MessageChan():
			p.logger.Info("Received OpAMP message",
				zap.String("type", msg.Type),
				zap.String("body", msg.Body),
				zap.String("capability", transformCapability))

			if msg.Type != transformMsgType {
				p.logger.Debug("Ignoring message with wrong type",
					zap.String("expected", transformMsgType),
					zap.String("got", msg.Type))
				continue
			}

			var statements struct {
				TraceStatements  []common.ContextStatements `json:"trace_statements" yaml:"trace_statements"`
				MetricStatements []common.ContextStatements `json:"metric_statements" yaml:"metric_statements"`
				LogStatements    []common.ContextStatements `json:"log_statements" yaml:"log_statements"`
			}

			// First try to unmarshal as YAML
			err := yaml.Unmarshal([]byte(msg.Body), &statements)
			if err != nil {
				// If that fails, try JSON
				err = json.Unmarshal([]byte(msg.Body), &statements)
				if err != nil {
					// Try parsing as flat format
					var flatConfig map[string][]string
					if err := yaml.Unmarshal([]byte(msg.Body), &flatConfig); err != nil {
						p.logger.Error("Failed to unmarshal transform statements (tried structured and flat formats)",
							zap.Error(err),
							zap.String("body", msg.Body))
						continue
					}

					// Convert flat format to structured
					for field, stmts := range flatConfig {
						switch field {
						case "trace_statements":
							statements.TraceStatements = []common.ContextStatements{{
								Context:     "span",
								Statements:  stmts,
								ErrorMode:   p.cfg.ErrorMode,
								SharedCache: true,
							}}
						case "metric_statements":
							statements.MetricStatements = []common.ContextStatements{{
								Context:     "metric",
								Statements:  stmts,
								ErrorMode:   p.cfg.ErrorMode,
								SharedCache: true,
							}}
						case "log_statements":
							statements.LogStatements = []common.ContextStatements{{
								Context:     "log",
								Statements:  stmts,
								ErrorMode:   p.cfg.ErrorMode,
								SharedCache: true,
							}}
						}
					}
				}
			}

			p.logger.Info("Parsed statements",
				zap.Int("trace_statements", len(statements.TraceStatements)),
				zap.Int("metric_statements", len(statements.MetricStatements)),
				zap.Int("log_statements", len(statements.LogStatements)),
				zap.Any("trace_statements_content", statements.TraceStatements))

			// Validate and create new processors before acquiring the lock
			var newLogProc *logs.Processor
			var newTraceProc *traces.Processor
			var newMetricProc *metrics.Processor

			if len(statements.TraceStatements) > 0 {
				// Create processor with statements - validation happens during creation
				newProc, err := traces.NewProcessor(statements.TraceStatements, p.cfg.ErrorMode, p.settings)
				if err != nil {
					p.logger.Error("Failed to create new traces processor",
						zap.Error(err),
						zap.Any("statements", statements.TraceStatements))
					errResp := ValidationError{
						Error: fmt.Sprintf("Failed to create new traces processor: %v", err),
						Type:  "trace_statements",
					}
					body, _ := json.Marshal(errResp)
					sendChan, err := p.opampClient.SendMessage("validation_error", body)
					if err != nil {
						p.logger.Error("Failed to send validation error", zap.Error(err))
					} else {
						p.logger.Debug("Sent validation error response")
						<-sendChan // Wait for the message to be sent
					}
					continue
				}
				p.logger.Info("Created new trace processor",
					zap.Any("statements", statements.TraceStatements),
					zap.Any("old_statements", p.cfg.TraceStatements))
				newTraceProc = newProc
			}

			if len(statements.MetricStatements) > 0 {
				// Create processor with statements - validation happens during creation
				newProc, err := metrics.NewProcessor(statements.MetricStatements, p.cfg.ErrorMode, p.settings)
				if err != nil {
					errResp := ValidationError{
						Error: fmt.Sprintf("Failed to create new metrics processor: %v", err),
						Type:  "metric_statements",
					}
					body, _ := json.Marshal(errResp)
					sendChan, err := p.opampClient.SendMessage("validation_error", body)
					if err != nil {
						p.logger.Error("Failed to send validation error", zap.Error(err))
					} else {
						p.logger.Debug("Sent validation error response")
						<-sendChan // Wait for the message to be sent
					}
					continue
				}
				newMetricProc = newProc
				p.logger.Info("Created new metric processor", zap.Any("statements", statements.MetricStatements))
			}

			if len(statements.LogStatements) > 0 {
				// Create processor with statements - validation happens during creation
				newProc, err := logs.NewProcessor(statements.LogStatements, p.cfg.ErrorMode, p.cfg.FlattenData, p.settings)
				if err != nil {
					errResp := ValidationError{
						Error: fmt.Sprintf("Failed to create new logs processor: %v", err),
						Type:  "log_statements",
					}
					body, _ := json.Marshal(errResp)
					sendChan, err := p.opampClient.SendMessage("validation_error", body)
					if err != nil {
						p.logger.Error("Failed to send validation error", zap.Error(err))
					} else {
						p.logger.Debug("Sent validation error response")
						<-sendChan // Wait for the message to be sent
					}
					continue
				}
				newLogProc = newProc
				p.logger.Info("Created new log processor", zap.Any("statements", statements.LogStatements))
			}

			// Only update processors if all validations passed
			p.opampMux.Lock()
			if newLogProc != nil {
				p.logsProcessor = newLogProc
				p.logger.Info("Updated logs processor with new configuration")
			}
			if newTraceProc != nil {
				p.logger.Info("Updating traces processor",
					zap.Any("old_processor", p.tracesProcessor),
					zap.Any("new_processor", newTraceProc),
					zap.Any("old_statements", p.cfg.TraceStatements),
					zap.Any("new_statements", statements.TraceStatements))
				p.tracesProcessor = newTraceProc
				p.cfg.TraceStatements = statements.TraceStatements
			}
			if newMetricProc != nil {
				p.metricsProcessor = newMetricProc
				p.logger.Info("Updated metrics processor with new configuration")
			}
			p.opampMux.Unlock()
			p.logger.Info("Finished processing OpAMP message successfully")
		}
	}
}

func (p *transformProcessor) Shutdown(context.Context) error {
	if p.opampClient != nil {
		p.opampClient.Unregister()
	}
	return nil
}

func (p *transformProcessor) ProcessLogs(ctx context.Context, ld plog.Logs) (plog.Logs, error) {
	p.opampMux.RLock()
	defer p.opampMux.RUnlock()

	if p.logsProcessor == nil {
		return ld, nil
	}
	return p.logsProcessor.ProcessLogs(ctx, ld)
}

func (p *transformProcessor) ProcessTraces(ctx context.Context, td ptrace.Traces) (ptrace.Traces, error) {
	p.opampMux.RLock()
	defer p.opampMux.RUnlock()

	if p.tracesProcessor == nil {
		p.logger.Debug("No traces processor configured")
		return td, nil
	}

	p.logger.Debug("Processing traces",
		zap.Any("processor", p.tracesProcessor),
		zap.Any("statements", p.cfg.TraceStatements))

	processed, err := p.tracesProcessor.ProcessTraces(ctx, td)
	if err != nil {
		p.logger.Error("Failed to process traces", zap.Error(err))
		return td, err
	}

	return processed, nil
}

func (p *transformProcessor) ProcessMetrics(ctx context.Context, md pmetric.Metrics) (pmetric.Metrics, error) {
	p.opampMux.RLock()
	defer p.opampMux.RUnlock()

	if p.metricsProcessor == nil {
		return md, nil
	}
	return p.metricsProcessor.ProcessMetrics(ctx, md)
}

type customMessageAdapter struct {
	msgChan chan *CustomMessage
	handler opampcustommessages.CustomCapabilityHandler
	done    chan struct{}
}

func (a *customMessageAdapter) MessageChan() <-chan *CustomMessage {
	return a.msgChan
}

func (a *customMessageAdapter) Unregister() {
	close(a.done)
	a.handler.Unregister()
}

func (a *customMessageAdapter) SendMessage(typ string, body []byte) (chan struct{}, error) {
	return a.handler.SendMessage(typ, body)
}
