package vmess

import (
	"io"
	"net"
)

func NewServerConn(raw net.Conn, command *Command) (*ServerConn, error) {
	c := &ServerConn{raw, raw, raw}

	if command.GetSecType() == SecTypeAES128CFB {
		stream, err := NewAesCfbEncStream(command.GetResponseCipherKey()[:16], command.GetResponseCipherIV()[:16])
		if err != nil {
			return nil, err
		}
		c.dataWriter = NewSecurityWriter(c.dataWriter, stream)

		stream, err = NewAesCfbDecStream(command.GetRequestCipherKey(), command.GetRequestCipherIV())
		if err != nil {
			return nil, err
		}
		c.dataReader = NewSecurityReader(c.dataReader, stream)
	}

	if command.HashOption(OptionS) {
		c.dataWriter = NewChunkWriter(c.dataWriter, NewChunkWithCommand(command, false, true))
		c.dataReader = NewChunkReader(c.dataReader, NewChunkWithCommand(command, false, false))
	}

	return c, nil
}

type ServerConn struct {
	net.Conn
	dataWriter io.Writer
	dataReader io.Reader
}

func (c *ServerConn) Read(buf []byte) (int, error) {
	return c.dataReader.Read(buf)
}

func (c *ServerConn) Write(buf []byte) (int, error) {
	return c.dataWriter.Write(buf)
}
