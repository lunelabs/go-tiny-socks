package authenticator

import (
	"context"
	"errors"
	"fmt"
	"github.com/lunelabs/go-tiny-socks/socks5"
	"io"
)

const (
	noAcceptable = uint8(255)
	NoAuth       = uint8(0)
)

var (
	NoSupportedAuth = errors.New("no supported authentication mechanism")
)

type Authenticator struct {
}

func NewAuthenticator() *Authenticator {
	return &Authenticator{}
}

func (a *Authenticator) Authenticate(
	conn io.Writer,
	bufConn io.Reader,
	authenticationHandler socks5.AuthenticationHandler,
) (*AuthContext, error) {
	methods, err := a.readMethods(bufConn)

	if err != nil {
		return nil, fmt.Errorf("Failed to get auth methods: %v", err)
	}

	for _, method := range methods {
		if authenticationHandler(context.Background(), method, nil) {
			_, err := conn.Write([]byte{socks5.Version, NoAuth})

			return &AuthContext{NoAuth, nil}, err
		}
	}

	return nil, a.noAcceptableAuth(conn)
}

func (a *Authenticator) readMethods(r io.Reader) ([]byte, error) {
	header := []byte{0}

	if _, err := r.Read(header); err != nil {
		return nil, err
	}

	numMethods := int(header[0])
	methods := make([]byte, numMethods)
	_, err := io.ReadAtLeast(r, methods, numMethods)

	return methods, err
}

func (a *Authenticator) noAcceptableAuth(conn io.Writer) error {
	conn.Write([]byte{socks5.Version, noAcceptable})

	return NoSupportedAuth
}
