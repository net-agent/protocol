package utils

import (
	"fmt"
	"net"
)

func Dial(addr string) (net.Conn, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial '%v' failed, err=%v", addr, err)
	}
	return c, nil
}
