package vmess

import (
	"bytes"
	"crypto/sha256"
	"io"
	"log"
	"net"
)

type ClientConn struct {
	*Client
	net.Conn

	command *Command

	dataWriter io.Writer
	dataReader io.Reader
}

func (c *ClientConn) Write(buf []byte) (int, error) {
	if c.dataWriter == nil {
		//
		// 使用AEAD发送认证信息和指令
		// 这部分信息不受security和transport设置的影响
		//
		err := c.writeCommand()
		if err != nil {
			log.Println("write vmess command to server failed: ", err)
			return 0, nil
		}

		c.dataWriter = c.Conn

		// AES-128-CFB是对整个数据块进行加密，所以先
		if c.command.GetSecType() == SecTypeAES128CFB {
			key := c.command.GetRequestCipherKey()
			iv := c.command.GetRequestCipherIV()
			stream, err := NewAesCfbEncStream(key, iv)
			if err != nil {
				return 0, err
			}
			c.dataWriter = NewSecurityWriter(c.dataWriter, stream)
		}

		if c.command.HashOption(OptionS) {
			c.dataWriter = NewChunkWriter(c.dataWriter, NewChunkWithCommand(c.command, true, true))
		}
	}

	return c.dataWriter.Write(buf)
}

func (c *ClientConn) writeCommand() error {
	header := bytes.NewBuffer(nil)
	_, err := c.command.WriteTo(header)
	if err != nil {
		return err
	}
	return SealAeadHeader(c.Conn, c.Client.cmdKey, header.Bytes())
}

func (c *ClientConn) Read(buf []byte) (int, error) {
	if c.dataReader == nil {
		//
		// VmessAEAD的应答包头是独立加密的
		//
		key := sha256.Sum256(c.command.GetRequestCipherKey())
		iv := sha256.Sum256(c.command.GetRequestCipherIV())
		headBuf, err := OpenAeadResponse(c.Conn, key[:16], iv[:16])
		if err != nil {
			log.Println("upgrade vmess reader failed: ", err)
			return 0, err
		}
		headBufReader := bytes.NewBuffer(headBuf)
		resp := NewResponse(c.command.GetResponseAuthV())
		resp.ReadFrom(headBufReader)

		c.dataReader = c.Conn

		// AES-128-CFB 是对整个数据包进行加密，包含mask、padding，所以应该在分块读取之前
		if c.command.GetSecType() == SecTypeAES128CFB {
			stream, err := NewAesCfbDecStream(key[:16], iv[:16])
			if err != nil {
				return 0, err
			}
			c.dataReader = NewSecurityReader(c.dataReader, stream)
		}

		// 构建数据接收信道
		if c.command.HashOption(OptionS) {
			c.dataReader = NewChunkReader(c.dataReader, NewChunkWithCommand(c.command, true, false))
		}
	}
	return c.dataReader.Read(buf)
}
