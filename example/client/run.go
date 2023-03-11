package main

import (
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/net-agent/protocol/utils"
	"github.com/net-agent/socks"
)

// 创建socks5服务，监听listen地址
func Run(listen string, dialer Dialer) error {
	s := socks.NewServer()

	requestCount := uint32(0)

	s.SetRequster(func(req socks.Request, ctx socks.Context) (net.Conn, error) {
		if req.GetCommand() != socks.ConnectCommand {
			return nil, socks.ErrReplyCmdNotSupported
		}

		i := atomic.AddUint32(&requestCount, 1)

		port := req.GetPort()
		typeVal, addrData := req.GetAddress()
		t := utils.NewAddrType(utils.ProtoSocksV5, typeVal)
		addr, err := utils.AddrString(t, addrData, port)
		if err != nil {
			log.Printf("[%d] connect failed.  invalid addrType='%v' rawVal='%v'\n", i, t, typeVal)
			return nil, err
		}
		start := time.Now()

		// 第一阶段：与代理服务器创建连接
		// TODO：此处可以对多个dialer进行负载均衡
		c, err := dialer.Connect()
		elaps := time.Since(start).Round(time.Millisecond)

		if err != nil {
			log.Printf("[%d] connect failed.  addr='%v' dur=%v\n", i, addr, elaps)
			return nil, err
		} else {
			log.Printf("[%d] connect success. addr='%v' dur=%v\n", i, addr, elaps)
		}

		// 第二阶段：将与代理服务器之间的连接进行升级
		c = dialer.Upgrade(c, t.Byte(dialer.Protocol()), addrData, port)
		return c, err
	})

	return s.ListenAndRun(listen)
}
