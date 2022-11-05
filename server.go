package go_tiny_socks

import (
	"bufio"
	"context"
	"fmt"
	"github.com/lunelabs/go-tiny-socks/authenticator"
	"github.com/lunelabs/go-tiny-socks/socks5"
	"github.com/pkg/errors"
	"io"
	"net"
	"strings"
)

type closeWriter interface {
	CloseWrite() error
}

type Server struct {
	authenticator         *authenticator.Authenticator
	authenticationHandler socks5.AuthenticationHandler
	dialHandler           socks5.DialHandler
	dnsHandler            socks5.DnsHandler
}

func NewServer(
	authenticationHandler socks5.AuthenticationHandler,
	dialHandler socks5.DialHandler,
	dnsHandler socks5.DnsHandler,
) *Server {
	return &Server{
		authenticator:         authenticator.NewAuthenticator(),
		authenticationHandler: authenticationHandler,
		dialHandler:           dialHandler,
		dnsHandler:            dnsHandler,
	}
}

func (s *Server) ListenAndServe(listen string) error {
	listener, err := net.Listen("tcp", listen)

	if err != nil {
		return errors.Wrap(err, "cant create listener")
	}

	for {
		conn, err := listener.Accept()

		if err != nil {
			return err
		}

		go s.ServeConnection(conn)
	}
}

func (s *Server) ServeConnection(conn net.Conn) error {
	defer conn.Close()

	bufConn := bufio.NewReader(conn)

	version := []byte{0}

	if _, err := bufConn.Read(version); err != nil {
		fmt.Println("[ERR] socks: Failed to get version byte: %v", err)

		return err
	}

	// Ensure we are compatible
	if version[0] != socks5.Version {
		err := fmt.Errorf("Unsupported SOCKS version: %v", version)

		fmt.Println(err)

		return err
	}

	// Authenticate the connection
	authContext, err := s.authenticator.Authenticate(conn, bufConn, s.authenticationHandler)

	if err != nil {
		err = fmt.Errorf("Failed to authenticate: %v", err)

		fmt.Println(err)

		return err
	}

	request, err := NewRequest(bufConn, conn)

	if err != nil {
		if err == unrecognizedAddrType {
			if err := s.sendReply(conn, addrTypeNotSupported, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
		}

		return fmt.Errorf("Failed to read destination address: %v", err)
	}

	request.AuthContext = authContext

	// Process the client request
	if err := s.handleRequest(request, conn); err != nil {
		err = fmt.Errorf("Failed to handle request: %v", err)

		fmt.Println(err)

		return err
	}

	return nil
}

// handleRequest is used for request processing after authentication
func (s *Server) handleRequest(req *Request, conn conn) error {
	ctx := context.Background()

	if req.Command == ConnectCommand {
		return s.handleConnect(ctx, conn, req)
	}

	if err := s.sendReply(conn, commandNotSupported, nil); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}

	return fmt.Errorf("Unsupported command: %v", req.Command)
}

// handleConnect is used to handle a connect command
func (s *Server) handleConnect(ctx context.Context, conn conn, req *Request) error {
	dest := req.DestAddr
	ctx = context.WithValue(ctx, "remote_ip", req.RemoteAddr.IP.String())

	if dest.FQDN != "" {
		dnsCtx, addr, err := s.dnsHandler(ctx, dest.FQDN)

		if err != nil {
			if err := s.sendReply(conn, hostUnreachable, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}

			return fmt.Errorf("Failed to resolve destination '%v': %v", dest.FQDN, err)
		}

		ctx = dnsCtx
		dest.IP = addr
	}

	hostname := req.DestAddr.FQDN

	if len(hostname) == 0 {
		hostname = dest.IP.String()
	}

	ctx = context.WithValue(ctx, "dest_hostname", hostname)
	ctx = context.WithValue(ctx, "dest_ip", dest.IP.String())

	dial := s.dialHandler
	target, err := dial(ctx, "tcp", dest.Address())

	if err != nil {
		msg := err.Error()
		resp := hostUnreachable

		if strings.Contains(msg, "refused") {
			resp = connectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = networkUnreachable
		}

		if err := s.sendReply(conn, resp, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}

		return fmt.Errorf("Connect to %v failed: %v", req.DestAddr, err)
	}

	defer target.Close()

	// Send success
	local := target.LocalAddr().(*net.TCPAddr)
	bind := AddrSpec{IP: local.IP, Port: local.Port}

	if err := s.sendReply(conn, successReply, &bind); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}

	// Start proxying
	errCh := make(chan error, 2)

	go s.proxy(target, req.bufConn, errCh)
	go s.proxy(conn, target, errCh)

	// Wait
	for i := 0; i < 2; i++ {
		e := <-errCh

		if e != nil {
			// return from this function closes target (and conn).
			return e
		}
	}

	return nil
}

// proxy is used to suffle data from src to destination, and sends errors
// down a dedicated channel
func (s *Server) proxy(dst io.Writer, src io.Reader, errCh chan error) {
	_, err := io.Copy(dst, src)

	if tcpConn, ok := dst.(closeWriter); ok {
		tcpConn.CloseWrite()
	}

	errCh <- err
}

// sendReply is used to send a reply message
func (s *Server) sendReply(w io.Writer, resp uint8, addr *AddrSpec) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = ipv4Address
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case addr.FQDN != "":
		addrType = fqdnAddress
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = ipv4Address
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = ipv6Address
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)

	default:
		return fmt.Errorf("Failed to format address: %v", addr)
	}

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = socks5.Version
	msg[1] = resp
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)

	// Send the message
	_, err := w.Write(msg)
	return err
}
