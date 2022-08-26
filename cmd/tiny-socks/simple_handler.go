package main

import (
	"context"
	"github.com/lunelabs/go-tiny-socks/authenticator"
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
