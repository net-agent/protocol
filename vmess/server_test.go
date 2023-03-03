package vmess

import (
	"fmt"
	"io"
	"log"
	"net"
	"testing"

	"github.com/net-agent/protocol/utils"
	"github.com/stretchr/testify/assert"
)

func TestSession(t *testing.T) {
	stopEcho := make(chan int, 1)
	host := "localhost"
	port := uint16(41305)
	runEchoServer(fmt.Sprintf("%v:%v", host, port), stopEcho)

	// init client
	id := "b831381d-6324-4d53-ad4f-8cda48b30811"
	tmp := `{
		"network": "tcp",
		"address": "127.0.0.1",
		"port": 20000,
		"path": "/download",
		"uuid": "%v",
		"security": "%v",
		"transport": "%v"
	}`

	tests := []struct {
		security string
		trasport string
	}{
		{"none", "stream"},
		{"none", "chunk"},
		{"none", "mask"},
		// {"none", "padding"}, // invalid config

		{"aes-128-cfb", "stream"},
		{"aes-128-cfb", "chunk"},
		{"aes-128-cfb", "mask"},
		// {"aes-128-cfb", "padding"}, // invalid config

		// {"aes-128-gcm", "stream"}, // invalid config
		{"aes-128-gcm", "chunk"},
		{"aes-128-gcm", "mask"},
		{"aes-128-gcm", "padding"},

		// {"chacha20-poly1305", "stream"}, // invalid config
		{"chacha20-poly1305", "chunk"},
		{"chacha20-poly1305", "mask"},
		{"chacha20-poly1305", "padding"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("test sec='%v' trans='%v'", tt.security, tt.trasport), func(t *testing.T) {
			buf := fmt.Sprintf(tmp, id, tt.security, tt.trasport)
			client, err := NewClientFromBytes([]byte(buf))
			if !assert.Nil(t, err) {
				return
			}

			// init server session
			session, err := NewSession(id)
			if !assert.Nil(t, err) {
				return
			}

			c1, c2 := net.Pipe()
			c1 = client.Upgrade(c1, utils.VmessAddrDomain, []byte(host), port)
			go session.Process(c2, nil)

			go func() {
				_, err = c1.Write([]byte("GET / HTTP/1.1\r\nHost: qq.com:80\r\n\r\n"))
				if !assert.Nil(t, err) {
					return
				}
			}()

			resp := make([]byte, 100)
			n, err := io.ReadAtLeast(c1, resp, 1)
			if !assert.Nil(t, err) {
				return
			}
			log.Println("response:", string(resp[:n]))
		})
	}
}
