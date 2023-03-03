package vless

import (
	"io"
	"net"
)

const (
	Version    = byte(0x00)
	CommandTCP = byte(0x01)
	CommandUDP = byte(0x02)
	CommandMux = byte(0x03)
)

type ClientConn struct {
	Client *Client
	net.Conn
	command *Command
	resp    *Response

	dataWriter io.Writer
	dataReader io.Reader
}

func (c *ClientConn) Write(buf []byte) (int, error) {
	if c.dataWriter == nil {
		c.command.WriteTo(c.Conn)
		c.dataWriter = c.Conn
	}

	return c.dataWriter.Write(buf)
}

func (c *ClientConn) Read(buf []byte) (int, error) {
	if c.dataReader == nil {
		c.resp.ReadFrom(c.Conn)
		c.dataReader = c.Conn
	}

	return c.dataReader.Read(buf)
}
