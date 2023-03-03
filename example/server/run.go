package main

import "net"

type Proxy interface {
	Process(net.Conn) error
}

func Run(listen string, p Proxy) error {
	return nil
}
