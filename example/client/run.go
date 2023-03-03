package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"sync/atomic"

	"github.com/net-agent/protocol/vmess"
	"github.com/net-agent/socks"
)

// 创建socks5服务，监听listen地址
func Run(listen string, dialer Dialer) error {
	s := socks.NewServer()
	var index uint32
	s.SetRequster(func(req socks.Request, ctx socks.Context) (net.Conn, error) {
		if req.GetCommand() != socks.ConnectCommand {
			return nil, socks.ErrReplyCmdNotSupported
		}
		i := atomic.AddUint32(&index, 1)
		port := req.GetPort()
		addrType, addrData := req.GetAddress()
		addr := ""
		switch addrType {
		case socks.IPv4:
			addrType = vmess.AddressIPv4
			addr = fmt.Sprintf("%v.%v.%v.%v:%v", addrData[0], addrData[1], addrData[2], addrData[3], port)
		case socks.IPv6:
			addrType = vmess.AddressIPv6
			addr = fmt.Sprintf("%v:%v", hex.EncodeToString(addrData), port)
		case socks.Domain:
			addrType = vmess.AddressDomain
			addr = fmt.Sprintf("%v:%v", string(addrData), port)
		default:
			return nil, errors.New("unknown address type")
		}

		c, err := dialer.Dial("tcp", addrType, addrData, port)
		if err != nil {
			log.Printf("[%v] dial failed.  addr='%v' err='%v'\n", i, addr, err)
		} else {
			log.Printf("[%v] dail success. addr='%v'\n", i, addr)
		}
		return c, err
	})

	return s.ListenAndRun(listen)
}
