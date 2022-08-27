package main

import (
	"context"
	"github.com/lunelabs/go-tiny-socks/authenticator"
	"github.com/pkg/errors"
	"golang.org/x/net/proxy"
	"net"
	"strings"
	"time"
)

type SimpleHandler struct {
}

func NewSimpleHandler() *SimpleHandler {
	return &SimpleHandler{}
}

func (s *SimpleHandler) AuthenticationHandler(
	ctx context.Context,
	method uint8,
	payload map[string]string,
) bool {
	return method == authenticator.NoAuth
}

func (s *SimpleHandler) DnsHandler(ctx context.Context, name string) (context.Context, net.IP, error) {
	if strings.HasSuffix(name, ".lt") {
		addr, err := net.ResolveIPAddr("ip", name)

		if err != nil {
			return ctx, nil, err
		}

		return ctx, addr.IP, err
	}

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(1000),
			}
			return d.DialContext(ctx, network, "194.145.240.6:53")
		},
	}

	addresses, err := r.LookupHost(context.Background(), name)

	if err != nil {
		return ctx, nil, err
	}

	var ips []net.IP

	for _, address := range addresses {
		ip := net.ParseIP(address)

		if ipv4 := ip.To4(); ipv4 != nil {
			ips = append(ips, ip)
		}
	}

	if len(ips) == 0 {
		return ctx, nil, errors.New("ip not found")
	}

	return ctx, ips[0], nil
}

func (s *SimpleHandler) DialHandler(ctx context.Context, net_, addr string) (net.Conn, error) {
	destHostname := ctx.Value("dest_hostname").(string)

	//fmt.Println("dest hostname:", ctx.Value("dest_hostname").(string))
	//fmt.Println("dest ip:", ctx.Value("dest_ip").(string))

	if strings.HasSuffix(destHostname, ".uk") {
		auth := new(proxy.Auth)
		auth.User = "1aa779fea336"
		auth.Password = "1791958a43"

		dialer, err := proxy.SOCKS5(
			"tcp",
			"195.210.106.23:12324",
			auth,
			proxy.Direct,
		)

		if err != nil {
			return nil, errors.Wrap(err, "can't connect to the proxy")
		}

		return dialer.Dial(net_, addr)
	}

	return net.Dial(net_, addr)
}
