package vmess

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAeadSealAndOpen(t *testing.T) {
	type sealfunc func(w io.Writer, key, iv []byte, plain []byte) error
	type openfunc func(r io.Reader, key, iv []byte) ([]byte, error)

	type pair struct {
		name string
		seal sealfunc
		open openfunc
	}
	funcPairs := []pair{
		{
			name: "test aead header",
			seal: func(w io.Writer, key, iv []byte, plain []byte) error {
				var cmdKey [16]byte
				copy(cmdKey[:], key)
				return SealAeadHeader(w, cmdKey, plain)
			},
			open: func(r io.Reader, key, iv []byte) ([]byte, error) {
				var cmdKey [16]byte
				copy(cmdKey[:], key)
				authBuf, err := OpenEAuId(r, cmdKey)
				if err != nil {
					return nil, err
				}
				return OpenAeadHeader(r, cmdKey, authBuf)
			},
		}, {
			name: "test aead response",
			seal: SealAeadResponse,
			open: OpenAeadResponse,
		},
	}

	for _, pair := range funcPairs {
		t.Run(pair.name, func(t *testing.T) {
			var key = make([]byte, 16)
			var iv = make([]byte, 16)
			var payload []byte = make([]byte, 1024)

			_, err := io.ReadFull(rand.Reader, payload)
			assert.Nil(t, err)

			aeadSend := bytes.NewBuffer(nil)
			err = pair.seal(aeadSend, key, iv, payload)
			assert.Nil(t, err)
			// assert.Equal(t, aeadSend.Len(), len(payload)+16)

			r := bytes.NewReader(aeadSend.Bytes())
			aeadRecv, err := pair.open(r, key, iv)
			assert.Nil(t, err)
			assert.True(t, bytes.Equal(payload, aeadRecv))
		})
	}
}
