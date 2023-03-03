package main

import (
	"log"
	"net"

	"github.com/net-agent/protocol/vmess"
)

func main() {
	log.Println("v2ray server started")

	session, err := vmess.NewSession("b831381d-6324-4d53-ad4f-8cda48b30811")
	if err != nil {
		log.Panic("create session failed:", err)
	}

	lis, err := net.Listen("tcp", "localhost:20000")
	if err != nil {
		log.Panic("listen failed:", err)
	}

	for {
		c, err := lis.Accept()
		if err != nil {
			log.Println("accept failed:", err)
			break
		}

		go session.Process(c, nil)
	}

	log.Println("v2ray server stopped")
}
