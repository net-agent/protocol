package vmess

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestClient(t *testing.T) {
	stopEcho := make(chan int, 1)
	host := "localhost"
	port := uint16(41305)
	runEchoServer(fmt.Sprintf("%v:%v", host, port), stopEcho)

	tmp := `{
		"net": "tcp",
		"add": "127.0.0.1",
		"port": 20000,
		"path": "/download",
		"id": "b831381d-6324-4d53-ad4f-8cda48b30811",
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
			buf := fmt.Sprintf(tmp, tt.security, tt.trasport)
			client, err := NewClientFromBytes([]byte(buf))
			assert.Nil(t, err, "parse client failed")
			if err != nil {
				return
			}

			c, err := client.Dial("tcp", AddressDomain, []byte(host), port)
			assert.Nil(t, err, "connect target failed")
			if err != nil {
				return
			}

			echoClientTest(t, c)
			c.Close()
		})
	}

	stopEcho <- 0
}

func echoClientTest(t *testing.T, c net.Conn) {
	// "GET / HTTP/1.1\r\nHost: qq.com:80\r\n\r\n"
	payload := []byte{71, 69, 84, 32, 47, 32, 72, 84, 84, 80, 47, 49, 46, 49, 13, 10, 72, 111, 115, 116, 58, 32, 113, 113, 46, 99, 111, 109, 58, 56, 48, 13, 10, 13, 10}

	// c.SetDeadline(time.Now().Add(time.Second * 10))
	n, err := c.Write(payload)
	if err != nil {
		t.Error("write http request failed", err)
		return
	}
	if n != len(payload) {
		t.Error("write payload not finished")
		return
	}

	buf := make([]byte, len(payload))
	_, err = io.ReadFull(c, buf)
	assert.Nil(t, err, "read http response failed")

	assert.Equal(t, buf, payload)

	firstline, _, _ := strings.Cut(string(buf), "\r\n")
	t.Logf("http response, size='%v' firstline:'%v'\n", n, firstline)
}

func runEchoServer(addr string, stop chan int) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}

	go func() {
		select {
		case <-stop:
		case <-time.After(time.Second * 20):
		}
		l.Close()
	}()

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				break
			}
			log.Println("new connection accepted")
			go io.Copy(c, c)
		}

		log.Println("test echo server stopped")
	}()
}
