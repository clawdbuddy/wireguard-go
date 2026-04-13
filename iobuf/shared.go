/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package iobuf

import (
	"errors"
	"sync/atomic"
	"unsafe"

	"github.com/tailscale/wireguard-go/waitpool"
)

var _ Recycler = (*Shared)(nil)

// Shared is a backing array that can be shared by multiple Views.
// It implements [Recycler] to return itself to the [Pool] when all Views referring to it are released.
type Shared struct {
	Bytes         Raw
	BytesRecycler Recycler
	Refs          atomic.Int32
}

// Refer sets b to refer to a slice of the backing array.
func (s *Shared) Refer(b *View, start, end int) {
	b.Recycler = s
	b.Handle = RecycleHandle(unsafe.Pointer(s))
	s.Refs.Add(1)
	b.Bytes = s.Bytes[start:end:end]
}

// Recycle is called by a View's Release when the View is no longer in use.
func (s *Shared) Recycle(ptr RecycleHandle) {
	if s.Refs.Add(-1) == 0 {
		s.BytesRecycler.Recycle(ptr) // return to pool
	}
}

func (s *Shared) Release() {
	s.Recycle(RecycleHandle(unsafe.Pointer(s)))
}

var (
	ErrInvalidSplitDimensions = errors.New("buffer: invalid split dimensions")
	ErrInsufficientBuffers    = errors.New("buffer: insufficient buffers")
)

// SplitCoalesced fills outBufs with non-overlapping slices of the backing array,
// where stride is the desired slice length, and readLen is the total length of data to split.
// The last slice may be shorter than stride if readLen is not a multiple of stride.
func (s *Shared) SplitCoalesced(vs []View, stride, readLen int) (n int, err error) {
	if stride <= 0 ||
		readLen > len(s.Bytes) ||
		stride > readLen {
		return 0, ErrInvalidSplitDimensions
	}
	numToSplit := (readLen + stride - 1) / stride
	if numToSplit > len(vs) {
		return 0, ErrInsufficientBuffers
	}
	start, end := 0, stride
	for i := range numToSplit {
		s.Refer(&vs[i], start, end)
		start = end
		end += stride
		if end > readLen {
			end = readLen
		}
		n++
	}
	return n, nil
}

// SharedBufPool is used for package-level [Get] and [EnsureAllocated].
var SharedBufPool = NewSharedBufferPool(MaxPooledBuffers)

// SharedBufferPool is a capped pool of backing arrays.
type SharedBufferPool struct {
	*waitpool.WaitPool
}

func NewSharedBufferPool(limit int) *SharedBufferPool {
	pool := &SharedBufferPool{}
	pool.WaitPool = waitpool.New(limit, func() any {
		p := new(Shared)
		p.BytesRecycler = pool
		return p
	})
	return pool
}

func (p *SharedBufferPool) Get() *Shared {
	arr := p.WaitPool.Get().(*Shared)
	arr.Refs.Store(1) // *SharedData must be Released as well.
	return arr
}

// Recycle returns the buffer to the pool.
//
//go:nocheckptr
func (p *SharedBufferPool) Recycle(ptr RecycleHandle) {
	arr := (*Shared)(unsafe.Pointer(ptr)) //nolint:govet
	p.Put(arr)
}
