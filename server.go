package go_tiny_socks

import (
	"bufio"
	"fmt"
	"github.com/lunelabs/go-tiny-socks/authenticator"
	"github.com/lunelabs/go-tiny-socks/socks5"
	"github.com/pkg/errors"
	"net"
)

type Server struct {
	authenticator         *authenticator.Authenticator
	authenticationHandler socks5.AuthenticationHandler
}

func NewServer(authenticationHandler socks5.AuthenticationHandler) *Server {
	return &Server{
		authenticator:         authenticator.NewAuthenticator(),
		authenticationHandler: authenticationHandler,
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

	request, err := NewRequest(bufConn)

	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(conn, addrTypeNotSupported, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
		}

		return fmt.Errorf("Failed to read destination address: %v", err)
	}

	request.AuthContext = authContext

	if client, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		request.RemoteAddr = &AddrSpec{IP: client.IP, Port: client.Port}
	}

	// Process the client request
	if err := s.handleRequest(request, conn); err != nil {
		err = fmt.Errorf("Failed to handle request: %v", err)

		fmt.Println(err)

		return err
	}

	return nil
}
