// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package splittest // import "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/split/splittest"

import (
	"bufio"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type Step struct {
	bufferSize int
	waitAtEOF  func() bool
	validate   validateFunc
}

type validateFunc func(t *testing.T, advance int, token []byte, err error)

func newStep(val validateFunc, opts ...StepOption) Step {
	s := Step{
		validate:  val,
		waitAtEOF: func() bool { return false },
	}
	for _, opt := range opts {
		opt(&s)
	}
	return s
}

func ExpectReadMore(opts ...StepOption) Step {
	return newStep(
		func(t *testing.T, advance int, token []byte, err error) {
			assert.True(t, needMoreData(advance, token, err))
		}, opts...)
}

func ExpectToken(expectToken string, opts ...StepOption) Step {
	return ExpectAdvanceToken(len(expectToken), expectToken, opts...)
}

func ExpectAdvanceToken(expectAdvance int, expectToken string, opts ...StepOption) Step {
	return newStep(
		func(t *testing.T, advance int, token []byte, err error) {
			assert.Equal(t, expectAdvance, advance)
			assert.Equal(t, []byte(expectToken), token)
			assert.NoError(t, err)
		}, opts...)
}

func ExpectAdvanceNil(expectAdvance int, opts ...StepOption) Step {
	return newStep(
		func(t *testing.T, advance int, token []byte, err error) {
			assert.Equal(t, expectAdvance, advance)
			assert.Equal(t, []byte(nil), token)
			assert.NoError(t, err)
		}, opts...)
}

func ExpectError(expectErr string, opts ...StepOption) Step {
	return newStep(
		func(t *testing.T, advance int, token []byte, err error) {
			assert.EqualError(t, err, expectErr)
		}, opts...)
}

type StepOption func(*Step)

func WithInitialBufferSize(bufferSize int) StepOption {
	return func(step *Step) {
		step.bufferSize = bufferSize
	}
}

func WithMaxDelay(maxTime time.Duration, tick time.Duration) StepOption {
	var waited time.Duration
	return func(step *Step) {
		step.waitAtEOF = func() bool {
			time.Sleep(maxTime)
			waited += tick
			return waited < maxTime
		}
	}
}

func New(splitFunc bufio.SplitFunc, input []byte, steps ...Step) func(*testing.T) {
	return func(t *testing.T) {
		var offset int
		for _, step := range append(steps, ExpectReadMore()) {
			// Split funcs do not have control over the size of the
			// buffer but they can behave differently because of it.
			// By default, start with a tiny buffer and grow it slowly
			// to ensure the split func is capable of asking appropriately.
			// However, a fixed buffer size can be specified for each
			// step in order to validate particular behaviors.
			bufferSize := 1
			if step.bufferSize > 0 {
				bufferSize = step.bufferSize
			}

			var atEOF bool
			var advance int
			var token []byte
			var err error
			for needMoreData(advance, token, err) && (!atEOF || step.waitAtEOF()) {
				data := make([]byte, 0, bufferSize)
				if offset+bufferSize >= len(input) {
					atEOF = true
					data = append(data, input[offset:]...)
				} else {
					data = append(data, input[offset:offset+bufferSize]...)
				}
				advance, token, err = splitFunc(data, atEOF)

				// Grow the buffer at a slow pace to ensure that we're
				// exercising the split func's ability to ask for more data.
				bufferSize = 1 + bufferSize + bufferSize/8
			}
			offset += advance
			step.validate(t, advance, token, err)
		}
	}
}

func needMoreData(advance int, token []byte, err error) bool {
	return advance == 0 && token == nil && err == nil
}

// ScanLinesStrict behaves like bufio.ScanLines except EOF is not considered a line ending.
func ScanLinesStrict(data []byte, atEOF bool) (advance int, token []byte, err error) {
	advance, token, err = bufio.ScanLines(data, atEOF)
	if advance == len(token) {
		return 0, nil, nil
	}
	return
}
