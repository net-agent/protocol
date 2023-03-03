package vmess

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

func NewShaker(key []byte) *Shaker {
	s := &Shaker{}
	s.hash = sha3.NewShake128()
	s.hash.Write(key) // safe
	// log.Println("new shaker key:", key)
	return s
}

type Shaker struct {
	hash  sha3.ShakeHash
	cache [8]byte
}

func (s *Shaker) NextByte() byte {
	s.hash.Read(s.cache[:1]) // safe
	return s.cache[0]
}
func (s *Shaker) NextUint16() uint16 {
	slice := s.cache[:2]
	s.hash.Read(slice)
	n := binary.BigEndian.Uint16(slice)
	return n
}
func (s *Shaker) NextUint32() uint32 {
	slice := s.cache[:4]
	s.hash.Read(slice)
	return binary.BigEndian.Uint32(slice)
}
func (s *Shaker) NextUint64() uint64 {
	slice := s.cache[:8]
	s.hash.Read(slice)
	return binary.BigEndian.Uint64(slice)
}
func (s *Shaker) Read(buf []byte) (int, error) {
	return s.hash.Read(buf)
}
