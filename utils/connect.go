package utils

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/net/websocket"
)

type Dialer func() (net.Conn, error)

func MakeDialer(network, address string, port uint16, path string) (Dialer, error) {
	target := ""
	switch network {
	case "tcp":
		target = fmt.Sprintf("%v:%v", address, port)
		return func() (net.Conn, error) {
			return net.Dial("tcp", target)
		}, nil
	case "ws":
		target = fmt.Sprintf("ws://%v:%v%v", address, port, path)
		return func() (net.Conn, error) {
			return websocket.Dial(target, "", "http://qq.com/")
		}, nil
	default:
		return nil, errors.New("invalid network")
	}
}
