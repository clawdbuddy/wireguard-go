//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net/netip"
	"testing"
)

type mockBind struct {
	sent      [][]byte
	receiveFn ReceiveFunc
	closed    bool
}

func (m *mockBind) Send(bufs [][]byte, _ Endpoint, offset int) error {
	for _, buf := range bufs {
		if len(buf) >= offset {
			m.sent = append(m.sent, buf[offset:])
		}
	}
	return nil
}

func (m *mockBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	fns := []ReceiveFunc{}
	if m.receiveFn != nil {
		fns = append(fns, m.receiveFn)
	}
	return fns, port, nil
}

func (m *mockBind) Close() error {
	m.closed = true
	return nil
}

func (m *mockBind) SetMark(mark uint32) error {
	return nil
}

func (m *mockBind) ParseEndpoint(s string) (Endpoint, error) {
	return &StdNetEndpoint{}, nil
}

func (m *mockBind) BatchSize() int {
	return 1
}

func TestObfuscatingBindSend(t *testing.T) {
	// Create a mock Bind that just records what was sent
	mock := &mockBind{
		sent: make([][]byte, 0),
	}

	obfuscating := NewObfuscatingBind(mock)

	// Create a test packet simulating WireGuard transport message
	// WireGuard transport header: Type(1) + Receiver(4) + Counter(8) = 16 bytes header
	buf := make([]byte, 128)
	buf[8] = MessageTransportType // Type 4 = transport
	buf[9] = 0x11                 // receiver bytes
	buf[10] = 0x11
	buf[11] = 0x11
	buf[12] = 0x11
	buf[16] = 1 // counter byte 0
	buf[17] = 0 // counter byte 1

	bufs := [][]byte{buf}
	ep := &StdNetEndpoint{}
	ep.AddrPort = netip.MustParseAddrPort("192.168.1.1:51820")

	err := obfuscating.Send(bufs, ep, 8)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if len(mock.sent) != 1 {
		t.Fatalf("Expected 1 packet sent, got %d", len(mock.sent))
	}

	sent := mock.sent[0]

	// First byte should be 0x40 (short header)
	if sent[0] != 0x40 {
		t.Errorf("Expected first byte 0x40, got 0x%02x", sent[0])
	}

	// Should have QUIC header (11 bytes) before WireGuard header
	// WireGuard header is at position 11 (after 11-byte QUIC short header)
	if len(sent) < 27 {
		t.Fatalf("Packet too short: %d bytes, need at least 27", len(sent))
	}
	if sent[11] != MessageTransportType {
		t.Errorf("Expected WireGuard type at offset 11, got 0x%02x", sent[11])
	}
}

func TestObfuscatingBindReceive(t *testing.T) {
	mock := &mockBind{}

	obfuscating := NewObfuscatingBind(mock)

	mock.receiveFn = func(packets [][]byte, sizes []int, eps []Endpoint) (int, error) {
		// Populate the packet with a QUIC-wrapped transport message
		buf := packets[0]
		buf[0] = 0x40 // Short header
		for i := 1; i <= 8; i++ {
			buf[i] = byte(i)
		}
		buf[9] = 0x01
		buf[10] = 0x00
		buf[11] = MessageTransportType
		sizes[0] = 27
		return 1, nil
	}

	fns, _, err := obfuscating.Open(51820)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if len(fns) != 1 {
		t.Fatalf("Expected 1 receive function, got %d", len(fns))
	}

	packets := [][]byte{make([]byte, 128)}
	sizes := []int{0}
	eps := []Endpoint{&StdNetEndpoint{}}

	written, err := fns[0](packets, sizes, eps)
	if err != nil {
		t.Fatalf("Wrapped receive failed: %v", err)
	}

	if written != 1 {
		t.Fatalf("Expected 1 packet, got %d", written)
	}

	// After stripping, the WireGuard type should be at position 0
	// and the size should be 27 - 11 = 16
	if sizes[0] != 16 {
		t.Errorf("Expected stripped size 16, got %d", sizes[0])
	}
	if packets[0][0] != MessageTransportType {
		t.Errorf("Expected WireGuard type at position 0, got 0x%02x", packets[0][0])
	}
}

// TestObfuscatingBindRoundTrip tests a full send+receive cycle.
func TestObfuscatingBindRoundTrip(t *testing.T) {
	// Simulate a full round-trip through the ObfuscatingBind.
	// Setup: create inner and outer Binds connected by a channel.
	sendBuf := make(chan []byte, 1)

	inner := &mockBind{
		receiveFn: func(packets [][]byte, sizes []int, eps []Endpoint) (int, error) {
			// This is the "network side" receive: packets arrive as raw UDP
			// We feed them from what the outer send produced
			buf, ok := <-sendBuf
			if !ok {
				return 0, nil
			}
			copy(packets[0], buf)
			sizes[0] = len(buf)
			return 1, nil
		},
	}

	outer := NewObfuscatingBind(inner)

	// ---- SEND ----
	// Create a WireGuard transport message at offset 8
	buf := make([]byte, 128)
	buf[8] = MessageTransportType
	buf[16] = 0x42 // counter bytes (at offset+8)
	buf[17] = 0x13
	buf[18] = 0x99 // payload

	ep := &StdNetEndpoint{}
	ep.AddrPort = netip.MustParseAddrPort("10.0.0.1:51820")

	err := outer.Send([][]byte{buf}, ep, 8)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	// Forward the QUIC-wrapped packet through the receive channel
	sendBuf <- inner.sent[0]

	// ---- RECEIVE ----
	fns, _, err := outer.Open(51820)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	packets := [][]byte{make([]byte, 128)}
	sizes := []int{0}
	eps := []Endpoint{&StdNetEndpoint{}}

	written, err := fns[0](packets, sizes, eps)
	if err != nil {
		t.Fatalf("Receive failed: %v", err)
	}

	if written != 1 {
		t.Fatalf("Expected 1 packet, got %d", written)
	}

	// Verify the data matches what we sent
	// Original: 128 bytes, QUIC hdr 11 bytes, so stripped = 117 bytes
	if sizes[0] != 117 {
		t.Fatalf("Expected size 117, got %d", sizes[0])
	}

	// The WireGuard type should be at position 0 (shifted from original offset 8)
	if packets[0][0] != MessageTransportType {
		t.Errorf("Expected type 4 at position 0, got 0x%02x", packets[0][0])
	}

	// Counter bytes (originally at buf[16..17]) should be at buf[8..9]
	if packets[0][8] != 0x42 || packets[0][9] != 0x13 {
		t.Errorf("Counter mismatch: got %x %x, expected 42 13", packets[0][8], packets[0][9])
	}

	// Payload byte (originally at buf[18]) should be at buf[10]
	if packets[0][10] != 0x99 {
		t.Errorf("Payload mismatch: got 0x%02x, expected 0x99", packets[0][10])
	}
}
