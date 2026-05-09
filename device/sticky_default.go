//go:build !linux

package device

import (
	"github.com/clawdbuddy/wireguard-go/conn"
	"github.com/clawdbuddy/wireguard-go/rwcancel"
)

func (device *Device) startRouteListener(bind conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
