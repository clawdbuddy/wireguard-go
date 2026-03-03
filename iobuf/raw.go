/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package iobuf

import (
	"unsafe"

	"github.com/tailscale/wireguard-go/waitpool"
)

var _ Recycler = (*RawPool)(nil)

// Raw is the fundamental byte array.
type Raw [MaxBufferSize]byte

// RawPool wraps [waitpool.WaitPool] of [Raw] buffers
// to configure their return via [Raw.Recycle].
type RawPool struct {
	*waitpool.WaitPool
}

func (p *RawPool) Get() *Raw {
	return p.WaitPool.Get().(*Raw)
}

// Recycle returns the buffer to the pool.
//
//go:nocheckptr
func (p *RawPool) Recycle(ptr RecycleHandle) {
	arr := (*Raw)(unsafe.Pointer(ptr)) //nolint:govet
	p.Put(arr)
}

func NewRawPool(size int) *RawPool {
	return &RawPool{waitpool.New(size, func() any {
		return new(Raw)
	})}
}

// DefaultRawPool is used for package-level [Get] and [EnsureAllocated].
var DefaultRawPool = NewRawPool(MaxBufferSize)

// EnsureAllocated fills zero-valued Views from the [DefaultRawPool].
func EnsureAllocated(bufs []View) {
	for i := range bufs {
		if bufs[i].Bytes == nil {
			Init(&bufs[i])
		}
	}
}

// Init initializes a [View] in-place with a fresh backing from the pool.
// Sets Bytes to the full backing array.
func Init(b *View) {
	arr := DefaultRawPool.Get()
	b.Recycler = DefaultRawPool
	b.Handle = RecycleHandle(unsafe.Pointer(arr))
	b.Bytes = arr[:]
}
