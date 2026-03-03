/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

// Package iobuf provides pooled packet buffers for the I/O pipeline.
// Each [View] carries one packet and a recycle function that returns
// its backing storage to the originating pool on [Release].
package iobuf

// RecycleHandle is the opaque reference to the [View] backing arrays.
type RecycleHandle uintptr

// Recycler returns a backing array for reuse.
// The argument is the Backing of the [View] being released.
type Recycler interface {
	Recycle(RecycleHandle)
}

// RecycleFunc is a function adapter for Recycler.
type RecycleFunc func(RecycleHandle)

func (f RecycleFunc) Recycle(ptr RecycleHandle) { f(ptr) }

// View is the packet envelope. Meant to be a value type,
// allocated once per goroutine and reused across read cycles.
type View struct {
	Recycler Recycler      // nil for external/unmanaged Views.
	Handle   RecycleHandle // zero for external/unmanaged Views.

	// Bytes holds the bounded packet data. Cut from the backing array,
	// it may be re-sliced by the caller. Do not append() on this slice.
	// Nil for uninitialized Views.
	Bytes []byte
}

// Release returns the backing data to its source and zeros the View.
func (b *View) Release() {
	if b.Recycler != nil {
		b.Recycler.Recycle(b.Handle)
	}
	*b = View{}
}

// Claim transfers ownership: returns a copy of the View and zeros the source.
func (b *View) Claim() View {
	c := *b
	*b = View{}
	return c
}

// ReleaseAll releases each View in the slice.
func ReleaseAll(bufs []View) {
	for i := range bufs {
		bufs[i].Release()
	}
}
