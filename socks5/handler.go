package socks5

import (
	"context"
	"net"
)

type AuthenticationHandler func(ctx context.Context, method uint8, payload map[string]string) bool
type DialHandler func(ctx context.Context, net_, addr string) (net.Conn, error)
type DnsHandler func(ctx context.Context, name string) (context.Context, net.IP, error)
