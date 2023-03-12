package main

import (
	"log"
	"net"

	"github.com/net-agent/protocol/utils"
	"github.com/net-agent/socks"
)

// 创建socks5服务，监听listen地址
func Run(listen string, dialer Dialer) error {
	s := socks.NewServer()

	s.SetRequster(func(req socks.Request, ctx socks.Context) (net.Conn, error) {
		if req.GetCommand() != socks.ConnectCommand {
			return nil, socks.ErrReplyCmdNotSupported
		}

		port := req.GetPort()
		typeVal, addrData := req.GetAddress()
		t := utils.NewAddrType(utils.ProtoSocksV5, typeVal)

		log.Printf("accepted. target='%v'\n", req.GetAddrPortStr())

		// 第一阶段：与代理服务器创建连接
		// TODO：此处可以对多个dialer进行负载均衡
		c, err := dialer.Connect()

		if err != nil {
			log.Println("connect failed:", err)
			return nil, err
		}

		// 第二阶段：将与代理服务器之间的连接进行升级
		c = dialer.Upgrade(c, t.Byte(dialer.Protocol()), addrData, port)
		return c, err
	})

	return s.ListenAndRun(listen)
}
