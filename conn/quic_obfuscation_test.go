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

	mock.receiveFn = func(packets [][]byte, s []int, e []Endpoint) (int, error) {
		return 1, nil
	}

	fns, _, err := obfuscating.Open(51820)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if len(fns) != 1 {
		t.Fatalf("Expected 1 receive function, got %d", len(fns))
	}

	// Create a QUIC-wrapped packet
	buf := make([]byte, 128)
	buf[0] = 0x40 // Short header
	for i := 1; i <= 8; i++ {
		buf[i] = byte(i)
	}
	buf[9] = 0x01
	buf[10] = 0x00
	buf[11] = MessageTransportType

	packets := [][]byte{buf}
	sizes := []int{27}
	eps := []Endpoint{&StdNetEndpoint{}}

	written, err := fns[0](packets, sizes, eps)
	if err != nil {
		t.Fatalf("Wrapped receive failed: %v", err)
	}

	if written != 1 {
		t.Errorf("Expected 1 packet, got %d", written)
	}
}
