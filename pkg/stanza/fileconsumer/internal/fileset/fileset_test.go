// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package fileset // import "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/fileconsumer/internal/fileset"

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/fileconsumer/internal/fingerprint"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/fileconsumer/internal/reader"
)

var (
	fpEmpty     = fingerprint.New([]byte(""))
	fpABC       = fingerprint.New([]byte("ABC"))
	fpABCDEF    = fingerprint.New([]byte("ABCDEF"))
	fpABCDEFGHI = fingerprint.New([]byte("ABCDEFGHI"))
	fpXYZ       = fingerprint.New([]byte("XYZ"))
)

func TestEmpty(t *testing.T) {
	set := New[*reader.Reader]()
	assert.Equal(t, 0, set.Len())

	assert.Nil(t, set.MatchExact(fpEmpty), "empty set should have no matches")
	assert.Equal(t, 0, set.Len(), "empty set should remain at length 0")
	assert.Nil(t, set.MatchPrefix(fpEmpty), "empty set should have no matches")
	assert.Equal(t, 0, set.Len(), "empty set should remain at length 0")

	assert.Nil(t, set.MatchExact(fpABCDEF), "empty set should have no matches")
	assert.Equal(t, 0, set.Len(), "empty set should remain at length 0")
	assert.Nil(t, set.MatchPrefix(fpABCDEF), "empty set should have no matches")
	assert.Equal(t, 0, set.Len(), "empty set should remain at length 0")
}

func TestAdd(t *testing.T) {
	set := New[*reader.Reader]()

	set.Add(newReader(fpABCDEF))
	assert.Equal(t, 1, set.Len(), "dding a reader should increment the length")

	set.Add(newReader(fpABCDEF))
	assert.Equal(t, 1, set.Len(), "dding the same reader again should not change the length")

	set.Add(newReader(fpABC))
	assert.Equal(t, 2, set.Len(), "dding a different reader should increment the length")

	set.Add(newReader(fpABC))
	assert.Equal(t, 2, set.Len(), "dding the same reader again should not change the length")

	set.Add(newReader(fpXYZ))
	assert.Equal(t, 3, set.Len(), "dding a different reader of the same length should increment the length")

	set.Add(newReader(fpXYZ))
	assert.Equal(t, 3, set.Len(), "dding the same reader again should not change the length")
}

func TestAll(t *testing.T) {
	set := New[*reader.Reader]()
	assert.Empty(t, set.All(), "empty set should return an empty slice")

	set.Add(newReader(fpABC))
	all := set.All()
	assert.Equal(t, 1, len(all), "should not remove elements from the set")
	assert.Equal(t, fpABC, all[0].GetFingerprint(), "adding a reader should return a slice with the added reader")

	set.Add(newReader(fpABCDEF))
	all = set.All()
	assert.Equal(t, 2, len(all), "should not remove elements from the set")
	assert.NotEqual(t, all[0].GetFingerprint(), all[1].GetFingerprint(), "returns set with distinct fingerprints")
}

func TestExact(t *testing.T) {
	set := New[*reader.Reader]()

	set.Add(newReader(fpABCDEF))
	assert.Nil(t, set.MatchExact(fpABC), "should not match prefixes")
	assert.Equal(t, 1, set.Len(), "failed match should not remove element from the set")
	assert.Equal(t, fpABCDEF, set.MatchExact(fpABCDEF).Fingerprint, "should return the reader with the exact fingerprint")
	assert.Equal(t, 0, set.Len(), "should remove the reader from the set")
	assert.Nil(t, set.MatchExact(fpABCDEF), "should return nil after the reader is removed")

	set.Add(newReader(fpABC))
	assert.Nil(t, set.MatchExact(fpABCDEF), "should not match prefixes")
	assert.Equal(t, 1, set.Len(), "failed match should not remove element from the set")
	assert.Equal(t, fpABC, set.MatchExact(fpABC).Fingerprint, "should find the exact match")
	assert.Equal(t, 0, set.Len(), "should remove the reader from the set")
	assert.Nil(t, set.MatchExact(fpABC), "should return nil after the reader is removed")
}

func TestMatchPrefix(t *testing.T) {
	set := New[*reader.Reader]()

	set.Add(newReader(fpABCDEF))
	assert.Nil(t, set.MatchPrefix(fpABC), "should NOT match when parameter is prefix of element")
	assert.Equal(t, 1, set.Len(), "failed match should not remove element from the set")

	assert.Equal(t, fpABCDEF, set.MatchPrefix(fpABCDEF).Fingerprint, "should return the reader with the exact fingerprint")
	assert.Equal(t, 0, set.Len(), "should remove the reader from the set")

	set.Add(newReader(fpABC))
	assert.Equal(t, fpABC, set.MatchPrefix(fpABCDEF).Fingerprint, "should return the reader with the matching prefix")
	assert.Equal(t, 0, set.Len(), "successful match should remove element from the set")
}

func TestMatchPrefixReturnsLongest(t *testing.T) {
	// Test when shorter inserted first
	set := New[*reader.Reader]()
	set.Add(newReader(fpABC))
	set.Add(newReader(fpABCDEF))
	assert.Equal(t, fpABCDEF, set.MatchPrefix(fpABCDEFGHI).Fingerprint, "should return the longest match")
	assert.Equal(t, fpABC, set.MatchPrefix(fpABCDEFGHI).Fingerprint, "should return the longest match")
	assert.Equal(t, 0, set.Len(), "should have removed the readers from the set")

	// Test when longer inserted first
	set = New[*reader.Reader]()
	set.Add(newReader(fpABCDEF))
	set.Add(newReader(fpABC))
	assert.Equal(t, fpABCDEF, set.MatchPrefix(fpABCDEFGHI).Fingerprint, "should return the longest match")
	assert.Equal(t, fpABC, set.MatchPrefix(fpABCDEFGHI).Fingerprint, "should return the longest match")
	assert.Equal(t, 0, set.Len(), "should have removed the readers from the set")
}

func newReader(fp *fingerprint.Fingerprint) *reader.Reader {
	return &reader.Reader{Metadata: &reader.Metadata{Fingerprint: fp}}
}
