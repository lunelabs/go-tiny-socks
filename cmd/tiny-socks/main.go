package main

import (
	"fmt"
	go_tiny_socks "github.com/lunelabs/go-tiny-socks"
	"os"
)

func main() {
	h := NewSimpleHandler()

	s := go_tiny_socks.NewServer(h.AuthenticationHandler)

	if err := s.ListenAndServe(":8888"); err != nil {
		fmt.Println(err)

		os.Exit(1)
	}
}
