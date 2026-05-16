//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestQUICBindOpenClose(t *testing.T) {
	b := NewQUICBind()
	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if port == 0 {
		t.Fatal("expected non-zero port")
	}
	if len(fns) != 2 {
		t.Fatalf("expected 2 ReceiveFuncs, got %d", len(fns))
	}

	if err := b.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

func TestQUICBindOpenTwice(t *testing.T) {
	b := NewQUICBind()
	_, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("first Open failed: %v", err)
	}
	_, _, err = b.Open(0)
	if err != ErrBindAlreadyOpen {
		t.Fatalf("expected ErrBindAlreadyOpen, got %v", err)
	}
	b.Close()
}

func TestQUICBindCloseIdempotent(t *testing.T) {
	b := NewQUICBind()
	b.Open(0)
	if err := b.Close(); err != nil {
		t.Fatalf("first Close failed: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
}

func TestQUICBindParseEndpoint(t *testing.T) {
	b := NewQUICBind()
	ep, err := b.ParseEndpoint("192.168.1.1:51820")
	if err != nil {
		t.Fatalf("ParseEndpoint failed: %v", err)
	}
	if ep.DstToString() != "192.168.1.1:51820" {
		t.Fatalf("unexpected dst: %s", ep.DstToString())
	}
	if ep.DstIP().String() != "192.168.1.1" {
		t.Fatalf("unexpected dst IP: %s", ep.DstIP())
	}
}

func TestQUICBindParseEndpointInvalid(t *testing.T) {
	b := NewQUICBind()
	_, err := b.ParseEndpoint("invalid-address")
	if err == nil {
		t.Fatal("expected error for invalid address")
	}
}

func TestQUICBindBatchSize(t *testing.T) {
	b := NewQUICBind()
	if b.BatchSize() != IdealBatchSize {
		t.Fatalf("expected %d, got %d", IdealBatchSize, b.BatchSize())
	}
}

func TestQUICBindSetMark(t *testing.T) {
	b := NewQUICBind()
	if err := b.SetMark(42); err != nil {
		t.Fatalf("SetMark failed: %v", err)
	}
}

func TestQUICBindHandshakeSendReceive(t *testing.T) {
	serverBind := NewQUICBind()
	serverFns, serverPort, err := serverBind.Open(0)
	if err != nil {
		t.Fatalf("server Open failed: %v", err)
	}
	defer serverBind.Close()

	clientBind := NewQUICBind()
	_, _, err = clientBind.Open(0)
	if err != nil {
		t.Fatalf("client Open failed: %v", err)
	}
	defer clientBind.Close()

	serverAddr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), serverPort)
	ep, err := clientBind.ParseEndpoint(serverAddr.String())
	if err != nil {
		t.Fatalf("ParseEndpoint failed: %v", err)
	}

	serverReceived := make(chan struct {
		data []byte
		ep   Endpoint
	}, 1)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		bufs := [][]byte{make([]byte, 1500)}
		sizes := []int{0}
		eps := []Endpoint{&StdNetEndpoint{}}
		n, rerr := serverFns[1](bufs, sizes, eps)
		if rerr != nil {
			t.Logf("server receiveHandshake error: %v", rerr)
			return
		}
		if n > 0 && sizes[0] > 0 {
			data := make([]byte, sizes[0])
			copy(data, bufs[0][:sizes[0]])
			serverReceived <- struct {
				data []byte
				ep   Endpoint
			}{data: data, ep: eps[0]}
		}
	}()

	handshakeMsg := []byte{
		1, 0, 0, 0,
		0xAA, 0xBB, 0xCC, 0xDD,
	}
	for i := 0; i < 140; i++ {
		handshakeMsg = append(handshakeMsg, byte(i))
	}

	sendErr := clientBind.Send([][]byte{handshakeMsg}, ep, 0)
	if sendErr != nil {
		t.Fatalf("client Send failed: %v", sendErr)
	}

	select {
	case recv := <-serverReceived:
		if len(recv.data) != len(handshakeMsg) {
			t.Fatalf("data length mismatch: got %d, want %d", len(recv.data), len(handshakeMsg))
		}
		if recv.data[0] != 1 {
			t.Fatalf("expected type 1, got %d", recv.data[0])
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for server to receive handshake")
	}

	wg.Wait()
}

func TestQUICBindTransportSendReceive(t *testing.T) {
	serverBind := NewQUICBind()
	serverFns, serverPort, err := serverBind.Open(0)
	if err != nil {
		t.Fatalf("server Open failed: %v", err)
	}
	defer serverBind.Close()

	clientBind := NewQUICBind()
	_, _, err = clientBind.Open(0)
	if err != nil {
		t.Fatalf("client Open failed: %v", err)
	}
	defer clientBind.Close()

	serverAddr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), serverPort)
	ep, err := clientBind.ParseEndpoint(serverAddr.String())
	if err != nil {
		t.Fatalf("ParseEndpoint failed: %v", err)
	}

	serverReceived := make(chan struct {
		data []byte
		ep   Endpoint
	}, 1)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		bufs := [][]byte{make([]byte, 1500)}
		sizes := []int{0}
		eps := []Endpoint{&StdNetEndpoint{}}
		n, rerr := serverFns[0](bufs, sizes, eps)
		if rerr != nil {
			t.Logf("server receiveTransport error: %v", rerr)
			return
		}
		if n > 0 && sizes[0] > 0 {
			data := make([]byte, sizes[0])
			copy(data, bufs[0][:sizes[0]])
			serverReceived <- struct {
				data []byte
				ep   Endpoint
			}{data: data, ep: eps[0]}
		}
	}()

	transportMsg := []byte{
		4, 0, 0, 0, // type = Transport
		0x11, 0x22, 0x33, 0x44, // receiver index
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // counter
	}
	for i := 0; i < 100; i++ {
		transportMsg = append(transportMsg, byte(i))
	}

	sendErr := clientBind.Send([][]byte{transportMsg}, ep, 0)
	if sendErr != nil {
		t.Fatalf("client Send failed: %v", sendErr)
	}

	select {
	case recv := <-serverReceived:
		if len(recv.data) != len(transportMsg) {
			t.Fatalf("data length mismatch: got %d, want %d", len(recv.data), len(transportMsg))
		}
		if recv.data[0] != 4 {
			t.Fatalf("expected type 4, got %d", recv.data[0])
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for server to receive transport message")
	}

	wg.Wait()
}

func TestQUICBindBidirectional(t *testing.T) {
	serverBind := NewQUICBind()
	serverFns, serverPort, err := serverBind.Open(0)
	if err != nil {
		t.Fatalf("server Open failed: %v", err)
	}
	defer serverBind.Close()

	clientBind := NewQUICBind()
	clientFns, clientPort, err := clientBind.Open(0)
	if err != nil {
		t.Fatalf("client Open failed: %v", err)
	}
	defer clientBind.Close()

	serverAddr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), serverPort)
	clientEP, err := clientBind.ParseEndpoint(serverAddr.String())
	if err != nil {
		t.Fatalf("client ParseEndpoint failed: %v", err)
	}

	clientAddr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), clientPort)
	serverEP, err := serverBind.ParseEndpoint(clientAddr.String())
	if err != nil {
		t.Fatalf("server ParseEndpoint failed: %v", err)
	}

	serverRecv := make(chan []byte, 1)
	clientRecv := make(chan []byte, 1)

	var serverWG sync.WaitGroup
	serverWG.Add(1)
	go func() {
		defer serverWG.Done()
		bufs := [][]byte{make([]byte, 1500)}
		sizes := []int{0}
		eps := []Endpoint{&StdNetEndpoint{}}
		n, rerr := serverFns[0](bufs, sizes, eps)
		if rerr == nil && n > 0 && sizes[0] > 0 {
			data := make([]byte, sizes[0])
			copy(data, bufs[0][:sizes[0]])
			serverRecv <- data
		}
	}()

	var clientWG sync.WaitGroup
	clientWG.Add(1)
	go func() {
		defer clientWG.Done()
		bufs := [][]byte{make([]byte, 1500)}
		sizes := []int{0}
		eps := []Endpoint{&StdNetEndpoint{}}
		n, rerr := clientFns[0](bufs, sizes, eps)
		if rerr == nil && n > 0 && sizes[0] > 0 {
			data := make([]byte, sizes[0])
			copy(data, bufs[0][:sizes[0]])
			clientRecv <- data
		}
	}()

	// Client sends transport to server
	clientMsg := []byte{
		4, 0, 0, 0,
		0x01, 0x02, 0x03, 0x04,
		0, 0, 0, 0, 0, 0, 0, 1,
		'C', 'L', 'I', 'E', 'N', 'T',
	}
	if err := clientBind.Send([][]byte{clientMsg}, clientEP, 0); err != nil {
		t.Fatalf("client Send failed: %v", err)
	}

	select {
	case data := <-serverRecv:
		if data[0] != 4 {
			t.Fatalf("server received wrong type: %d", data[0])
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout: server did not receive client message")
	}
	serverWG.Wait()

	// Server sends transport back to client
	serverMsg := []byte{
		4, 0, 0, 0,
		0x05, 0x06, 0x07, 0x08,
		0, 0, 0, 0, 0, 0, 0, 2,
		'S', 'E', 'R', 'V', 'E', 'R',
	}
	if err := serverBind.Send([][]byte{serverMsg}, serverEP, 0); err != nil {
		t.Fatalf("server Send failed: %v", err)
	}

	select {
	case data := <-clientRecv:
		if data[0] != 4 {
			t.Fatalf("client received wrong type: %d", data[0])
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout: client did not receive server message")
	}
	clientWG.Wait()
}

func TestQUICBindOffsetSend(t *testing.T) {
	serverBind := NewQUICBind()
	serverFns, serverPort, err := serverBind.Open(0)
	if err != nil {
		t.Fatalf("server Open failed: %v", err)
	}
	defer serverBind.Close()

	clientBind := NewQUICBind()
	_, _, err = clientBind.Open(0)
	if err != nil {
		t.Fatalf("client Open failed: %v", err)
	}
	defer clientBind.Close()

	serverAddr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), serverPort)
	ep, err := clientBind.ParseEndpoint(serverAddr.String())
	if err != nil {
		t.Fatalf("ParseEndpoint failed: %v", err)
	}

	serverReceived := make(chan []byte, 1)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		bufs := [][]byte{make([]byte, 1500)}
		sizes := []int{0}
		eps := []Endpoint{&StdNetEndpoint{}}
		n, rerr := serverFns[0](bufs, sizes, eps)
		if rerr == nil && n > 0 && sizes[0] > 0 {
			data := make([]byte, sizes[0])
			copy(data, bufs[0][:sizes[0]])
			serverReceived <- data
		}
	}()

	payload := []byte{4, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD, 0, 0, 0, 0, 0, 0, 0, 1}
	offset := 8
	buf := make([]byte, offset+len(payload))
	copy(buf[offset:], payload)

	if err := clientBind.Send([][]byte{buf}, ep, offset); err != nil {
		t.Fatalf("Send with offset failed: %v", err)
	}

	select {
	case data := <-serverReceived:
		if data[0] != 4 {
			t.Fatalf("wrong type, got %d", data[0])
		}
		if len(data) != len(payload) {
			t.Fatalf("data length mismatch: got %d, want %d", len(data), len(payload))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for server to receive message")
	}

	wg.Wait()
}

func TestQUICBindCloseUnblocksReceive(t *testing.T) {
	b := NewQUICBind()
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		bufs := [][]byte{make([]byte, 1500)}
		sizes := []int{0}
		eps := []Endpoint{&StdNetEndpoint{}}
		_, rerr := fns[0](bufs, sizes, eps)
		done <- rerr
	}()

	time.Sleep(100 * time.Millisecond)
	b.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error after close, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: receive did not unblock after close")
	}
}
