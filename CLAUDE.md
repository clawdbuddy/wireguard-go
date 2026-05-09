# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
make          # Build wireguard-go binary (generates version.go first)
make test     # Run all tests: go test ./...
go build      # Simple build
go test -v ./...        # Verbose tests
go test -race -v ./...  # Race detector tests (CI runs this)
go test -run TestName   # Run specific test
go run ./cmd/check-lockorder  # Static analysis for lock ordering
```

## Architecture Overview

This is a Go implementation of WireGuard. The codebase is organized into several packages:

### Core Packages

- **device/** - Core WireGuard protocol implementation
  - `device.go` - Main `Device` struct managing peers, routing tables, encryption queues, and TUN device
  - `peer.go` - `Peer` struct with keypairs, handshake state, timers, and packet queues
  - `noise-protocol.go` - Noise protocol handshake implementation (Curve25519, ChaCha20-Poly1305)
  - `send.go` - Outbound packet flow: TUN → Routing → Nonce → Encryption → UDP
  - `receive.go` - Inbound packet flow: UDP → Decryption → TUN
  - `allowedips.go` - Cryptokey Routing table (public key → allowed IPs)
  - `cookie.go` - Anti-handshake flooding cookies
  - `timers.go` - Handshake retransmission/keepalive timers
  - `afalg/` - Linux AF_ALG acceleration for ChaCha20-Poly1305 (ARM)

- **conn/** - Network connection abstraction
  - `conn.go` - `Bind` interface (UDP listener), `Endpoint` interface (peer address caching)
  - `bind_std.go` - Standard UDP bind implementation
  - Platform-specific: `bind_windows.go`, bound interface support

- **tun/** - TUN device abstraction
  - `tun.go` - `Device` interface for reading/writing IP packets
  - Platform-specific: `tun_linux.go`, `tun_darwin.go`, `tun_freebsd.go`, `tun_openbsd.go`, `tun_windows.go`
  - `netstack/` - gVisor-based netstack implementation for userspace networking
  - `offload_linux.go` - GRO/GSO offload handling

- **ipc/** - UAPI Unix socket interface for configuration
  - `uapi_unix.go`, `uapi_linux.go`, `uapi_bsd.go` - Unix socket listener for `wg` tool communication
  - `uapi_windows.go` - Windows named pipe implementation

### Supporting Packages

- **ratelimiter/** - Per-peer packet rate limiting
- **replay/** - Anti-replay window (sliding bitfield)
- **rwcancel/** - Read/write cancellation for fd monitoring
- **tai64n/** - TAI64N timestamp library

### Tools

- **cmd/check-lockorder/** - Static analysis tool for lock ordering violations

## Key Concepts

### Packet Flow (Outbound)
1. Read IP packet from TUN device
2. Cryptokey Routing lookup (destination IP → peer public key)
3. Encrypt via Noise protocol (sequential nonce assignment, parallel encryption)
4. Send encrypted UDP datagram to peer endpoint

### Packet Flow (Inbound)
1. Receive UDP datagram via Bind
2. Decrypt via Noise protocol
3. Validate anti-replay window
4. Write IP packet to TUN device

### Device State
- `deviceStateDown` → `deviceStateUp` → `deviceStateClosed`
- State transitions protected by `device.state.mu`

### Peer State Machine
- Handshake: initiation → response → finished
- Keypairs: old → current → next (for seamless rotation)

### Lock Ordering Rules
The `cmd/check-lockorder` tool enforces: `device.peers.mu` must never be acquired while holding `device.state.mu`. See `device/deadlock_test.go` for the annotated lock order graph.

## Platform Notes

- **Linux**: Uses kernel TUN if available; `device/afalg/` provides hardware acceleration
- **macOS**: Uses utun driver; interface names must be `utun[0-9]+` or `utun`
- **Windows**: Uses Wintun adapter via `golang.zx2c4.com/wintun`
- **OpenBSD/FreeBSD**: Uses native tun driver

## Environment Variables

- `LOG_LEVEL=debug|verbose|error|silent` - Logging level
- `WG_TUN_FD` - File descriptor for existing TUN device
- `WG_UAPI_FD` - File descriptor for UAPI socket
- `WG_PROCESS_FOREGROUND=1` - Run in foreground mode
