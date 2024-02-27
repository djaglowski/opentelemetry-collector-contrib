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
	readers []map[uint64]T
	len     int
}

func New[T Matchable](fpSize int) *Fileset[T] {
	return &Fileset[T]{readers: make([]map[uint64]T, fpSize+1)}
}

func (set *Fileset[T]) Len() int {
	return set.len
}

func (set *Fileset[T]) Add(readers ...T) {
	for _, r := range readers {
		fp := r.GetFingerprint()
		lenReaders := set.readers[fp.Len()]
		if lenReaders == nil {
			set.readers[fp.Len()] = map[uint64]T{fp.Hash(): r}
			set.len++
			return
		}
		if _, ok := lenReaders[fp.Hash()]; ok {
			return // already exists
		}
		lenReaders[fp.Hash()] = r
		set.len++
	}
}

func (set *Fileset[T]) All() []T {
	readers := make([]T, 0, set.len)
	for _, lenReaders := range set.readers {
		for _, reader := range lenReaders {
			readers = append(readers, reader)
		}
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
	for i := len(set.readers) - 1; i > 0; i-- {
		for hash, match := range set.readers[i] {
			if fp.StartsWith(match.GetFingerprint()) {
				delete(set.readers[i], hash)
				set.len--
				return match
			}
		}
	}
	return
}

func (set *Fileset[T]) findExact(fp *fingerprint.Fingerprint) (m T, ok bool) {
	if set.readers[fp.Len()] == nil {
		return
	}

	m, ok = set.readers[fp.Len()][fp.Hash()]
	if !ok {
		return
	}

	delete(set.readers[fp.Len()], fp.Hash())
	set.len--
	return
}
