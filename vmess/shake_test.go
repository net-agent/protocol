package vmess

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShake(t *testing.T) {
	key := []byte{1, 2, 3, 4}
	s1 := NewShaker(key)
	s2 := NewShaker(key)

	buf := make([]byte, 16)
	s1.Read(buf)

	b8a := s2.NextByte()
	b8b := s2.NextByte()
	b16 := s2.NextUint16()
	b32 := s2.NextUint32()
	b64 := s2.NextUint64()

	assert.Equal(t, b8a, buf[0])
	assert.Equal(t, b8b, buf[1])
	assert.Equal(t, b16, binary.BigEndian.Uint16(buf[2:4]))
	assert.Equal(t, b32, binary.BigEndian.Uint32(buf[4:8]))
	assert.Equal(t, b64, binary.BigEndian.Uint64(buf[8:16]))
}
