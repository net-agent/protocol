package vless

import (
	"encoding/binary"
	"io"
)

const MinCommandSize = 1 + 16 + 1 + 0 + 1 + 2 + 1 + 1 + 0
const MaxCommandSize = MinCommandSize + 255
const (
	AddressIPv4   = byte(0)
	AddressIPv6   = byte(1)
	AddressDomain = byte(2)
)

type Command struct {
	buf  [MaxCommandSize]byte
	size int
}

func NewCommand(uuid []byte, cmd byte, addrType byte, addrData []byte, port uint16) *Command {
	c := &Command{}

	c.buf[0] = Version
	copy(c.buf[1:17], uuid[:])
	c.buf[17] = 0
	c.buf[18] = cmd
	binary.BigEndian.PutUint16(c.buf[19:21], port)
	c.buf[21] = addrType

	c.size = 22

	addrLen := byte(len(addrData))
	if addrType == AddressDomain {
		c.buf[c.size] = byte(addrLen)
		c.size += 1
	}

	copy(c.buf[c.size:], addrData)
	c.size += int(addrLen)

	return c
}

func (c *Command) Bytes() []byte        { return c.buf[:c.size] }
func (c *Command) GetAddressType() byte { return c.buf[21] }
func (c *Command) GetAddressSize() byte { return c.buf[22] }

func (c *Command) ReadFrom(r io.Reader) (int64, error) {
	c.size = 0

	readed := int64(0)
	n, err := io.ReadFull(r, c.buf[:MinCommandSize])
	readed += int64(n)
	if err != nil {
		return readed, err
	}

	tailSize := 0
	switch c.GetAddressType() {
	case AddressDomain:
		tailSize += int(c.GetAddressSize())
	case AddressIPv4:
		tailSize += 3
	case AddressIPv6:
		tailSize += 15
	}

	if tailSize > 0 {
		n, err = io.ReadFull(r, c.buf[readed:readed+int64(tailSize)])
		readed += int64(n)
		if err != nil {
			return readed, err
		}
	}

	return readed, nil
}

func (c *Command) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(c.Bytes())
	return int64(n), err
}
