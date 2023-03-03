package vmess

import (
	"io"
	"log"
	"math/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecurity(t *testing.T) {
	c1, c2 := net.Pipe()

	key := make([]byte, 16)
	iv := make([]byte, 16)
	payload := make([]byte, 1024*1024)

	rand.Read(key)
	rand.Read(iv)
	// rand.Read(payload)

	go func(c net.Conn) {
		s, _ := NewAesCfbEncStream(key, iv)
		w := NewSecurityWriter(c, s)
		w.Write(payload)
		log.Println("write done")
	}(c1)

	s, _ := NewAesCfbDecStream(key, iv)
	r := NewSecurityReader(c2, s)
	buf := make([]byte, 1024*1024)
	io.ReadFull(r, buf)
	log.Println("read done")

	assert.Equal(t, payload, buf)
}
