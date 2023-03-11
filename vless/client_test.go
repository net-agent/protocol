package vless

import (
	"log"
	"sync"
	"testing"

	"github.com/net-agent/protocol/utils"
	"github.com/stretchr/testify/assert"
)

func TestClient(t *testing.T) {
	client, err := NewClientFromBytes([]byte(`{
		"v":    1,
		"net":  "tcp",
		"add":  "localhost",
		"port": 20000,
		"path": "",
		"id":   "b831381d-6324-4d53-ad4f-8cda48b30811"}`))
	assert.Nil(t, err)

	httpTest(t, client)
}

func httpTest(t *testing.T, client *Client) {
	c, err := client.Dial("tcp", utils.VlessAddrDomain, []byte("qq.com"), 80)
	assert.Nil(t, err)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		_, err = c.Write([]byte("GET / HTTP/1.1\r\nHost: qq.com:80\r\n\r\n"))
		assert.Nil(t, err)
		wg.Done()
	}()

	buf := make([]byte, 1024)
	n, err := c.Read(buf)
	assert.Nil(t, err)
	log.Println("resp:", string(buf[:n]))

	wg.Wait()
}
