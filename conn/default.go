//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

import "os"

func NewDefaultBind() Bind {
	if os.Getenv("WG_QUIC_TRANSPORT") != "" {
		return NewQUICBind()
	}
	if os.Getenv("WG_QUIC_OBFUSCATION") != "" {
		return NewObfuscatingBind(NewStdNetBind())
	}
	return NewStdNetBind()
}
