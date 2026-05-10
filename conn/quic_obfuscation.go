//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"crypto/sha256"
	"encoding/binary"
	"log"
	"sync"
)

// ObfuscatingBind wraps a Bind and adds/strips QUIC-style obfuscation headers.
// This is intended for use in environments where WireGuard traffic needs to
// be disguised as QUIC traffic for censorship circumvention.
type ObfuscatingBind struct {
	Bind

	// connectionIDs maps endpoint addresses to connection IDs
	connectionIDs   map[string][8]byte
	connectionIDsMu sync.RWMutex
}

var _ Bind = (*ObfuscatingBind)(nil)

// NewObfuscatingBind creates a new ObfuscatingBind wrapping the provided Bind.
func NewObfuscatingBind(bind Bind) *ObfuscatingBind {
	log.Printf("WireGuard QUIC obfuscation enabled")
	return &ObfuscatingBind{
		Bind:          bind,
		connectionIDs: make(map[string][8]byte),
	}
}

const (
	// QUIC header sizes
	quicCIDLength   = 8  // Connection ID length
	quicShortHdrLen = 11 // Short header: 1 + CID + 2 (pkn varint)
	quicLongHdrLen  = 17 // Long header (Initial): 1 + 4 + 1 + 8 + 2 + 1 (token)
)

// deriveConnectionID derives an 8-byte connection ID from an endpoint's address.
// This allows QUIC-style connection identification without actual QUIC protocol.
func deriveConnectionID(ep Endpoint) [8]byte {
	h := sha256.Sum256(ep.DstToBytes())
	var cid [8]byte
	copy(cid[:], h[:8])
	return cid
}

func (b *ObfuscatingBind) getConnectionID(ep Endpoint) [8]byte {
	addr := ep.DstToString()
	b.connectionIDsMu.RLock()
	cid, ok := b.connectionIDs[addr]
	b.connectionIDsMu.RUnlock()
	if ok {
		return cid
	}
	cid = deriveConnectionID(ep)
	b.connectionIDsMu.Lock()
	b.connectionIDs[addr] = cid
	b.connectionIDsMu.Unlock()
	return cid
}

// Send implements Bind.Send. It prepends a QUIC-like header to each packet.
func (b *ObfuscatingBind) Send(bufs [][]byte, ep Endpoint, offset int) error {
	cid := b.getConnectionID(ep)

	for _, buf := range bufs {
		if len(buf) < offset {
			continue
		}

		// Determine if this is a handshake message (types 1-3) or transport (type 4)
		// WireGuard header: Type at buf[offset], receiver at offset+4, counter at offset+8
		msgType := buf[offset]

		var quicHdrLen int
		if msgType >= MessageInitiationType && msgType <= MessageCookieReplyType {
			// Handshake message - use long header format
			// Byte 0: 0xC0 | type (1=Initial, 2=Handshake, 3=0-RTT)
			// For WireGuard, we use type 1 (Initial) for all handshake messages
			quicHdrLen = quicLongHdrLen
		} else if msgType == MessageTransportType {
			// Transport message - use short header format
			quicHdrLen = quicShortHdrLen
		} else {
			// Unknown type, skip obfuscation
			continue
		}

		packetLen := len(buf) - offset

		// Copy packet data to make room for QUIC header at position 0
		// Original: [prefix zeros][WireGuard at offset][content]
		// After:    [QUIC header][WireGuard at offset][content]
		// Use min of packetLen and available space
		copyLen := packetLen
		if quicHdrLen+copyLen > len(buf) {
			copyLen = len(buf) - quicHdrLen
		}
		copy(buf[quicHdrLen:quicHdrLen+copyLen], buf[offset:offset+copyLen])

		// Write QUIC header at position 0
		if msgType >= MessageInitiationType && msgType <= MessageCookieReplyType {
			// Long header format for handshake
			buf[0] = 0xC0 | 0x01 // Initial packet type
			// Version (4 bytes) - 0x00000001 for QUIC v1
			buf[1] = 0x00
			buf[2] = 0x00
			buf[3] = 0x00
			buf[4] = 0x01
			// Connection ID length (1 byte)
			buf[5] = quicCIDLength
			// Connection ID (8 bytes)
			copy(buf[6:6+quicCIDLength], cid[:])
			// Token length (1 byte) - 0 for no token
			buf[14] = 0x00
			// Packet number (2 bytes varint)
			counter := binary.LittleEndian.Uint64(buf[quicHdrLen+8:])
			binary.LittleEndian.PutUint16(buf[15:], uint16(counter))
		} else {
			// Short header format for transport
			// Byte 0: 0x40 (short header form)
			buf[0] = 0x40
			// Connection ID (8 bytes)
			copy(buf[1:1+quicCIDLength], cid[:])
			// Packet number (2 bytes varint)
			counter := binary.LittleEndian.Uint64(buf[quicHdrLen+8:])
			binary.LittleEndian.PutUint16(buf[9:], uint16(counter))
		}
	}

	// Send from position 0 (QUIC header is now at the front)
	return b.Bind.Send(bufs, ep, 0)
}

// Open implements Bind.Open. It wraps the underlying ReceiveFuncs to strip
// QUIC-like headers from incoming packets.
func (b *ObfuscatingBind) Open(port uint16) (fns []ReceiveFunc, actualPort uint16, err error) {
	fns, actualPort, err = b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}

	// Wrap each ReceiveFunc to strip QUIC headers
	for i, fn := range fns {
		fns[i] = b.wrapReceiveFunc(fn)
	}

	return fns, actualPort, nil
}

func (b *ObfuscatingBind) wrapReceiveFunc(fn ReceiveFunc) ReceiveFunc {
	var strippedTotal int64

	return func(packets [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		n, err = fn(packets, sizes, eps)
		if err != nil || n == 0 {
			return n, err
		}

		stripped := 0
		for i := 0; i < n; i++ {
			packet := packets[i]
			size := sizes[i]
			if size < 1 {
				continue
			}

			firstByte := packet[0]

			var quicHdrLen int
			if (firstByte & 0x80) != 0 {
				quicHdrLen = quicLongHdrLen
			} else if (firstByte & 0x40) != 0 {
				quicHdrLen = quicShortHdrLen
			} else {
				continue
			}

			if size <= quicHdrLen {
				continue
			}

			stripped++

			wgLen := size - quicHdrLen
			copy(packet[:wgLen], packet[quicHdrLen:size])
			sizes[i] = wgLen
		}

		if stripped > 0 {
			strippedTotal += int64(stripped)
			log.Printf("WireGuard QUIC obfuscation: stripped %d QUIC headers (total: %d)", stripped, strippedTotal)
		}

		return n, nil
	}
}

// SetMark implements Bind.SetMark by delegating to the underlying Bind.
func (b *ObfuscatingBind) SetMark(mark uint32) error {
	return b.Bind.SetMark(mark)
}

// ParseEndpoint implements Bind.ParseEndpoint by delegating to the underlying Bind.
func (b *ObfuscatingBind) ParseEndpoint(s string) (Endpoint, error) {
	return b.Bind.ParseEndpoint(s)
}

// BatchSize returns the batch size of the underlying Bind.
func (b *ObfuscatingBind) BatchSize() int {
	return b.Bind.BatchSize()
}

// Close implements Bind.Close by delegating to the underlying Bind.
func (b *ObfuscatingBind) Close() error {
	return b.Bind.Close()
}
