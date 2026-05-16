//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	quicIdleTimeout      = 5 * time.Minute
	quicKeepAlive        = 30 * time.Second
	quicHandshakeTimeout = 10 * time.Second

	quicHandshakeStream = 0
	quicTransportStream = 1

	quicRecvBufSize = 256
)

var _ Bind = (*QUICBind)(nil)
var _ Endpoint = (*StdNetEndpoint)(nil)

type quicSession struct {
	conn      quic.Connection
	ep        Endpoint
	closeOnce sync.Once
	done      chan struct{}
}

type quicPacket struct {
	data []byte
	ep   Endpoint
}

type QUICBind struct {
	mu       sync.Mutex
	listener *quic.Listener
	port     uint16

	sessions map[string]*quicSession

	handshakeCh chan quicPacket
	transportCh chan quicPacket

	tlsConfig  *tls.Config
	quicConfig *quic.Config

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewQUICBind() Bind {
	tlsConfig := newQUICTLSConfig()
	return &QUICBind{
		sessions:    make(map[string]*quicSession),
		handshakeCh: make(chan quicPacket, quicRecvBufSize),
		transportCh: make(chan quicPacket, quicRecvBufSize),
		tlsConfig:   tlsConfig,
		quicConfig: &quic.Config{
			HandshakeIdleTimeout: quicHandshakeTimeout,
			MaxIdleTimeout:       quicIdleTimeout,
			KeepAlivePeriod:      quicKeepAlive,
			MaxIncomingStreams:   64,
			EnableDatagrams:      true,
		},
	}
}

func (b *QUICBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.listener != nil {
		return nil, 0, ErrBindAlreadyOpen
	}

	b.ctx, b.cancel = context.WithCancel(context.Background())

	addr := netip.AddrPortFrom(netip.IPv6Unspecified(), port)
	udpAddr := net.UDPAddrFromAddrPort(addr)
	udpConn, err := net.ListenUDP(udpAddr.Network(), udpAddr)
	if err != nil {
		b.cancel()
		return nil, 0, err
	}

	ln, err := quic.Listen(udpConn, b.tlsConfig, b.quicConfig)
	if err != nil {
		udpConn.Close()
		b.cancel()
		return nil, 0, err
	}

	b.listener = ln
	b.port = uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)

	b.wg.Add(1)
	go b.acceptLoop()

	fns := []ReceiveFunc{
		b.receiveTransport,
		b.receiveHandshake,
	}

	return fns, b.port, nil
}

func (b *QUICBind) Close() error {
	b.mu.Lock()
	listener := b.listener
	if listener == nil {
		b.mu.Unlock()
		return nil
	}
	sessions := make([]*quicSession, 0, len(b.sessions))
	for _, s := range b.sessions {
		sessions = append(sessions, s)
	}
	b.mu.Unlock()

	b.cancel()

	for _, s := range sessions {
		s.closeOnce.Do(func() {
			close(s.done)
			s.conn.CloseWithError(0, "closing")
		})
	}

	b.wg.Wait()

	b.mu.Lock()
	err := listener.Close()
	b.listener = nil
	b.port = 0
	b.sessions = make(map[string]*quicSession)
	b.mu.Unlock()

	return err
}

func (b *QUICBind) Send(bufs [][]byte, ep Endpoint, offset int) error {
	epStr := ep.DstToString()

	b.mu.Lock()
	session, exists := b.sessions[epStr]
	b.mu.Unlock()

	if !exists {
		var err error
		session, err = b.dialSession(ep)
		if err != nil {
			return err
		}
	}

	select {
	case <-session.done:
		b.mu.Lock()
		delete(b.sessions, epStr)
		b.mu.Unlock()
		return errors.New("QUIC session closed")
	default:
	}

	for _, buf := range bufs {
		if len(buf) <= offset {
			continue
		}
		msg := buf[offset:]
		if len(msg) == 0 {
			continue
		}

		msgType := msg[0]

		switch {
		case msgType >= MessageInitiationType && msgType <= MessageCookieReplyType:
			if err := b.sendHandshake(session, msg); err != nil {
				return err
			}
		case msgType == MessageTransportType:
			if err := session.conn.SendDatagram(msg); err != nil {
				return err
			}
		}
	}

	return nil
}

func (b *QUICBind) sendHandshake(session *quicSession, msg []byte) error {
	ctx, cancel := context.WithTimeout(b.ctx, quicHandshakeTimeout)
	defer cancel()

	stream, err := session.conn.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}

	if _, err := stream.Write(msg); err != nil {
		stream.Close()
		return err
	}

	return stream.Close()
}

func (b *QUICBind) dialSession(ep Endpoint) (*quicSession, error) {
	ctx, cancel := context.WithTimeout(b.ctx, quicHandshakeTimeout)
	defer cancel()

	addr := ep.DstToString()
	conn, err := quic.DialAddr(ctx, addr, b.tlsConfig, b.quicConfig)
	if err != nil {
		return nil, err
	}

	session := &quicSession{
		conn: conn,
		ep:   ep,
		done: make(chan struct{}),
	}

	b.mu.Lock()
	b.sessions[ep.DstToString()] = session
	b.mu.Unlock()

	b.wg.Add(1)
	go b.sessionReadLoop(session)

	return session, nil
}

func (b *QUICBind) sessionReadLoop(session *quicSession) {
	defer b.wg.Done()

	streamCtx, streamCancel := context.WithCancel(b.ctx)
	defer streamCancel()

	go b.streamReader(session, streamCtx)

	for {
		data, err := session.conn.ReceiveDatagram(b.ctx)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return
			}
			select {
			case <-b.ctx.Done():
				return
			default:
				continue
			}
		}

		msg := make([]byte, len(data))
		copy(msg, data)

		select {
		case b.transportCh <- quicPacket{data: msg, ep: session.ep}:
		default:
		}
	}
}

func (b *QUICBind) streamReader(session *quicSession, ctx context.Context) {
	for {
		stream, err := session.conn.AcceptUniStream(ctx)
		if err != nil {
			return
		}

		go func(s quic.ReceiveStream) {
			defer s.CancelRead(0)

			data, err := io.ReadAll(s)
			if err != nil || len(data) == 0 {
				return
			}

			msg := make([]byte, len(data))
			copy(msg, data)

			select {
			case b.handshakeCh <- quicPacket{data: msg, ep: session.ep}:
			default:
			}
		}(stream)
	}
}

func (b *QUICBind) acceptLoop() {
	defer b.wg.Done()

	for {
		conn, err := b.listener.Accept(b.ctx)
		if err != nil {
			return
		}

		raddr := conn.RemoteAddr()
		udpAddr := raddr.(*net.UDPAddr)
		addrPort := udpAddr.AddrPort()
		ep := &StdNetEndpoint{AddrPort: addrPort}

		session := &quicSession{
			conn: conn,
			ep:   ep,
			done: make(chan struct{}),
		}

		b.mu.Lock()
		b.sessions[ep.DstToString()] = session
		b.mu.Unlock()

		b.wg.Add(1)
		go b.sessionReadLoop(session)
	}
}

func (b *QUICBind) receiveHandshake(packets [][]byte, sizes []int, eps []Endpoint) (int, error) {
	for i := range packets {
		packets[i] = packets[i][:cap(packets[i])]
	}

	select {
	case pkt, ok := <-b.handshakeCh:
		if !ok {
			return 0, net.ErrClosed
		}
		n := copy(packets[0], pkt.data)
		sizes[0] = n
		eps[0] = pkt.ep

		count := 1
		for i := 1; i < len(packets); i++ {
			select {
			case pkt, ok := <-b.handshakeCh:
				if !ok {
					return count, nil
				}
				n := copy(packets[i], pkt.data)
				sizes[i] = n
				eps[i] = pkt.ep
				count++
			default:
				return count, nil
			}
		}
		return count, nil

	case <-b.ctx.Done():
		return 0, net.ErrClosed
	}
}

func (b *QUICBind) receiveTransport(packets [][]byte, sizes []int, eps []Endpoint) (int, error) {
	for i := range packets {
		packets[i] = packets[i][:cap(packets[i])]
	}

	select {
	case pkt, ok := <-b.transportCh:
		if !ok {
			return 0, net.ErrClosed
		}
		n := copy(packets[0], pkt.data)
		sizes[0] = n
		eps[0] = pkt.ep

		count := 1
		for i := 1; i < len(packets); i++ {
			select {
			case pkt, ok := <-b.transportCh:
				if !ok {
					return count, nil
				}
				n := copy(packets[i], pkt.data)
				sizes[i] = n
				eps[i] = pkt.ep
				count++
			default:
				return count, nil
			}
		}
		return count, nil

	case <-b.ctx.Done():
		return 0, net.ErrClosed
	}
}

func (b *QUICBind) BatchSize() int {
	return IdealBatchSize
}

func (b *QUICBind) SetMark(mark uint32) error {
	return nil
}

func (b *QUICBind) ParseEndpoint(s string) (Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &StdNetEndpoint{AddrPort: e}, nil
}

func newQUICTLSConfig() *tls.Config {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		NextProtos:         []string{"wireguard-quic"},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	}
}
