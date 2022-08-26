package socks5

import "context"

type AuthenticationHandler func(ctx context.Context, method uint8, payload map[string]string) bool
type DnsHandler func(ctx context.Context, password string) bool
type DialHandler func(ctx context.Context, password string) bool
