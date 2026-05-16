/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"github.com/clawdbuddy/wireguard-go/device/afalg"
	"golang.org/x/sys/unix"
)

// On Linux, run the shared AEAD compatibility test suite against the
// AF_ALG-backed implementation in addition to the Go reference.
// If the kernel does not support AF_ALG or the chacha20-poly1305
// algorithm, the AF_ALG constructor is silently omitted (CI runner
// images may lack the necessary kernel crypto modules).
func init() {
	fd, err := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return
	}
	unix.Close(fd)

	a, err := afalg.New(make([]byte, 32))
	if err != nil {
		return
	}
	// Close the probe instance to avoid leaking the bind fd.
	// runtime.SetFinalizer on *aead would eventually close it,
	// but we can be deterministic here. Since close is unexported,
	// we rely on the GC.
	_ = a

	aeadCtors = append(aeadCtors, aeadCtorEntry{"af_alg", afalg.New})
}
