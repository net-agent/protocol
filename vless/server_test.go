package vless

import (
	"errors"
	"net"
	"testing"
)

func TestServer(t *testing.T) {
	var uuid [16]byte

	// 模拟网络创建连接的过程
	dialchan := make(chan net.Conn, 3)
	listenChan := make(chan net.Conn, 3)
	go func() {
		for {
			c1, c2 := net.Pipe()
			dialchan <- c1
			listenChan <- c2
		}
	}()

	// init client
	client := &Client{}
	client.userid = uuid[:]
	client.dial = func() (net.Conn, error) {
		c, ok := <-dialchan
		if !ok {
			return nil, errors.New("dial failed")
		}
		return c, nil
	}

	// init server
	sess := &Session{}
	copy(sess.uuid[:], uuid[:])

	// server loop
	go func() {
		for {
			c, ok := <-listenChan
			if !ok {
				return
			}

			sess.Process(c)
		}
	}()

	// client test
	httpTest(t, client)
}
