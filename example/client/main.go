package main

import (
	"fmt"
	"log"
	"net"

	"github.com/net-agent/protocol/utils"
	"github.com/net-agent/protocol/vless"
	"github.com/net-agent/protocol/vmess"
)

const (
	ProtocolSocks5 = byte(0)
	ProtocolVMess  = byte(1)
	ProtocolVLESS  = byte(2)
)

type Dialer interface {
	// Dial = Connect + Upgrade
	Dial(network string, addrType byte, addrData []byte, port uint16) (net.Conn, error)
	Connect() (net.Conn, error)
	Upgrade(c net.Conn, addrType byte, addrData []byte, port uint16) net.Conn
	Protocol() utils.ProtocolType
}

func main() {
	// 解析命令行参数
	listen, config, err := ParseFlag()
	if err != nil {
		panic(err)
	}

	var dialer Dialer
	switch config.Protocol {
	case "vless":
		dialer, err = vless.NewClientFromBytes(config.Bytes())
	case "vmess":
		dialer, err = vmess.NewClientFromBytes(config.Bytes())
	default:
		err = fmt.Errorf("unknown protocol: '%v'", config.Protocol)
	}
	if err != nil {
		panic(err)
	}

	proxy := fmt.Sprintf("%v %v://%v:%v%v", config.Protocol, config.Network, config.Address, config.Port, config.Path)
	log.Println("socks server running")
	log.Println("listen:", listen)
	log.Println("proxy:", proxy)

	Run(listen, dialer)
}
