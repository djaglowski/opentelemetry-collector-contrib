// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package fileset // import "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/fileconsumer/internal/fileset"

import (
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/fileconsumer/internal/fingerprint"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/fileconsumer/internal/reader"
)

var (
	_ Matchable = (*reader.Reader)(nil)
	_ Matchable = (*reader.Metadata)(nil)
)

type Matchable interface {
	GetFingerprint() *fingerprint.Fingerprint
}

type Fileset[T Matchable] struct {
	readers map[uint64]T
}

func New[T Matchable]() *Fileset[T] {
	return &Fileset[T]{readers: make(map[uint64]T, 10)}
}

func (set *Fileset[T]) Len() int {
	return len(set.readers)
}

func (set *Fileset[T]) Add(readers ...T) {
	for _, r := range readers {
		set.readers[r.GetFingerprint().Hash()] = r
	}
}

func (set *Fileset[T]) All() []T {
	readers := make([]T, 0, len(set.readers))
	for _, reader := range set.readers {
		readers = append(readers, reader)
	}
	return readers
}

func (set *Fileset[T]) MatchExact(fp *fingerprint.Fingerprint) (m T) {
	m, _ = set.findExact(fp)
	return
}

func (set *Fileset[T]) MatchPrefix(fp *fingerprint.Fingerprint) (m T) {
	if exact, ok := set.findExact(fp); ok {
		return exact
	}

	var longestHash uint64
	for hash, match := range set.readers {
		if !fp.StartsWith(match.GetFingerprint()) {
			continue
		}
		if longestHash == 0 {
			longestHash = hash
			continue
		}
		if match.GetFingerprint().Len() > set.readers[longestHash].GetFingerprint().Len() {
			longestHash = hash
		}
	}
	m = set.readers[longestHash]
	delete(set.readers, longestHash)
	return
}

func (set *Fileset[T]) findExact(fp *fingerprint.Fingerprint) (m T, ok bool) {
	m, ok = set.readers[fp.Hash()]
	if !ok {
		return
	}
	delete(set.readers, fp.Hash())
	return
}
