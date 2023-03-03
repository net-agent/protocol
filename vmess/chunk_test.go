package vmess

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestChunk(t *testing.T) {
	createChunk := func(mask, padding, fnv bool) *Chunk {
		c := NewChunk()
		if mask {
			c.EnableMask(nil, padding)
		}
		if fnv {
			c.EnableFnvSum()
		}
		return c
	}
	testchunk := func(t *testing.T, dataSize int, mask, padding, fnv bool) {
		data := make([]byte, dataSize)
		_, err := rand.Read(data)
		if err != nil {
			t.Error("rand.Read failed:", err)
			return
		}

		c1 := createChunk(mask, padding, fnv)
		c1.SetData(data)
		buf := bytes.NewBuffer(nil)

		_, err = c1.WriteTo(buf)
		if err != nil {
			t.Error("chunk.WriteTo failed:", err)
			return
		}

		c2 := createChunk(mask, padding, fnv)
		_, err = c2.ReadFrom(buf)
		if err != nil {
			t.Error("chunk.ReadFrom failed:", err)
			return
		}
		if !bytes.Equal(data, c2.Data()) {
			t.Error("data not equal")
			return
		}
	}

	tests := []struct {
		dataSize           int
		mask, padding, fnv bool
	}{
		{0, false, false, false},
		{1, false, false, false},
		{100, false, false, true},

		{0, true, false, false},
		{1, true, false, false},
		{100, true, false, true},

		{0, true, true, false},
		{1, true, true, false},
		{100, true, true, true},
	}

	for index, tt := range tests {
		t.Run(fmt.Sprintf("test case %v", index), func(t *testing.T) {
			testchunk(t, tt.dataSize, tt.mask, tt.padding, tt.fnv)
		})
	}
}

func TestChunkReadWriter(t *testing.T) {
	c1, c2 := net.Pipe()
	t.Run("test normal pipe", func(t *testing.T) {
		testReadWriteCloser(t, c1, c2)
	})

	t.Run("test chunk pipe", func(t *testing.T) {
		c3, c4 := net.Pipe()
		shakeKey1 := []byte{1, 2, 3}
		// shakeKey2 := []byte{3, 2, 1}
		testReadWriteCloser(t,
			NewChunkReadWriteCloser(c3,
				NewChunk().EnableMask(shakeKey1, false),
				NewChunk().EnableMask(shakeKey1, false),
			),
			NewChunkReadWriteCloser(c4,
				NewChunk().EnableMask(shakeKey1, false),
				NewChunk().EnableMask(shakeKey1, false),
			),
		)
	})
}

func testReadWriteCloser(t *testing.T, c1, c2 io.ReadWriteCloser) {
	chunkSize := 1024
	chunkCount := 10
	payloadLen := chunkCount * chunkSize
	payload := make([]byte, payloadLen)
	rand.Read(payload)

	go func(writer io.WriteCloser) {
		total := 0
		for total < payloadLen {
			n, err := writer.Write(payload[total : total+chunkSize])
			total += n
			if err != nil {
				t.Error("write failed:", err)
				return
			}
		}
		log.Println("write done. total=", total)
	}(c1)

	done := make(chan byte, 1)
	go func(reader io.ReadCloser) {
		var total int
		var err error
		defer func() {
			log.Println("read done, total=", total, "err=", err)
			reader.Close()
			done <- 0
		}()
		buf := make([]byte, payloadLen)
		total, err = io.ReadFull(reader, buf)
		if err != nil && err != io.EOF {
			assert.Nil(t, err, "readfull failed")
			return
		}
		if total != payloadLen {
			t.Error("data size not equal")
			return
		}
		if !bytes.Equal(payload, buf) {
			t.Error("data content not equal")
			return
		}
	}(c1)

	go io.Copy(c2, c2)

	select {
	case <-done:
	case <-time.After(time.Second * 5):
		t.Error("wait done timeout")
	}
}
