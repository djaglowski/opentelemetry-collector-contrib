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

package operatortest // import "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/operator/operatortest"

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/confmaptest"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/operator"
)

// ConfigUnmarshalTest is used for testing golden configs
type ConfigUnmarshalTests struct {
	DefaultConfig interface{}
	TestsFile     string
	Tests         []ConfigUnmarshalTest
}

// ConfigUnmarshalTest is used for testing golden configs
type ConfigUnmarshalTest struct {
	Name      string
	Expect    interface{}
	ExpectErr bool
}

// Run Unmarshals yaml files and compares them against the expected.
func (c ConfigUnmarshalTests) Run(t *testing.T) {
	testConfMaps, err := confmaptest.LoadConf(c.TestsFile)
	require.NoError(t, err)

	for _, tc := range c.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			testConfMap, err := testConfMaps.Sub(tc.Name)
			require.NoError(t, err)
			require.NotZero(t, len(testConfMap.AllKeys()), fmt.Sprintf("config not found: '%s'", tc.Name))

			var anyOpCfg *anyOpConfig
			var anyStCfg *anyStructConfig
			testCfg, opTest := c.DefaultConfig.(operator.Builder)
			if opTest {
				anyOpCfg = newAnyOpConfig(testCfg)
			} else {
				anyStCfg = newAnyStructConfig(c.DefaultConfig)
				anyOpCfg = newAnyOpConfig(anyStCfg)
				require.NoError(t, testConfMap.Merge(confmapTypeOverride))
			}

			err = config.UnmarshalReceiver(testConfMap, anyOpCfg)

			switch {
			case tc.ExpectErr:
				require.Error(t, err)
			case opTest:
				require.Equal(t, tc.Expect, anyOpCfg.Operator.Builder)
			default:
				require.Equal(t, tc.Expect, anyStCfg.TestStruct)
			}
		})
	}
}

type anyOpConfig struct {
	config.ReceiverSettings `mapstructure:",squash"`
	Operator                operator.Config `mapstructure:"operator"`
}

func newAnyOpConfig(opCfg operator.Builder) *anyOpConfig {
	return &anyOpConfig{
		ReceiverSettings: config.NewReceiverSettings(config.NewComponentID("any_op")),
		Operator:         operator.Config{Builder: opCfg},
	}
}

func (a *anyOpConfig) Unmarshal(component *confmap.Conf) error {
	return a.Operator.Unmarshal(component)
}

// anyStructConfig is a wrapper that satisfies the operator.Builder
// interface. The interface is not meant to be called, but allows
// any struct to be unmarshaled via confmap.UnmarshalReceiver
type anyStructConfig struct {
	OpType     string      `mapstructure:"type"`
	TestStruct interface{} `mapstructure:"test_struct"`
}

func newAnyStructConfig(testStruct interface{}) *anyStructConfig {
	return &anyStructConfig{TestStruct: testStruct}
}

var _ operator.Builder = (*anyStructConfig)(nil)

func (c *anyStructConfig) Build(_ *zap.SugaredLogger) (operator.Operator, error) {
	return nil, nil
}

func (c *anyStructConfig) ID() string {
	return ""
}

func (c *anyStructConfig) SetID(id string) {
}

func (c *anyStructConfig) Type() string {
	return c.OpType
}

// This is used to satisfy the requirement that "type" be set in the confmap
var confmapTypeOverride = confmap.NewFromStringMap(
	map[string]interface{}{
		"type": "any_op",
	},
)

// This registers the fake operator in the operator registry so that it can be unmarshaled
func init() {
	operator.Register("any_op", func() operator.Builder { return newAnyStructConfig(nil) })
}
