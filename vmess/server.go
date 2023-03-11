package vmess

import (
	"errors"
	"io"
	"log"
	"net"
	"time"

	"github.com/net-agent/protocol/utils"
)

func NewSession(id string) (*Session, error) {
	s := &Session{}
	userid, err := utils.ParseUUID(id)
	if err != nil {
		return nil, err
	}
	copy(s.cmdKey[:], GenCmdKey(userid))
	return s, nil
}

type Session struct {
	cmdKey [16]byte
}

// 处理已经通过认证的链接
func (s *Session) Process(c net.Conn, authBuf []byte) error {
	defer c.Close()
	var err error

	// 如果没有传入authBuf，则需要从authBuf认证开始进行读取
	if len(authBuf) == 0 {
		authBuf, err = s.Authentication(c)
		if err != nil {
			return err
		}
	}

	cmd, err := s.ReadCommand(c, authBuf)
	if err != nil {
		return err
	}

	t := utils.NewAddrType(utils.ProtoVmess, cmd.GetAddressType())
	addr := utils.AddrString(t, cmd.addressData, cmd.GetPort())

	target, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("dial failed:  %v\n", addr)
		return err
	}
	defer target.Close()
	log.Printf("dial success: %v\n", addr)

	if err := s.WriteResponse(c, cmd); err != nil {
		return err
	}

	client, err := NewServerConn(c, cmd)
	if err != nil {
		return err
	}

	rn, wn, err := utils.LinkReadWriter(client, target)
	log.Printf("closed: %v, %v readed, %v written, err=%v\n", addr, rn, wn, err)
	return err
}

func (s *Session) Authentication(r io.Reader) ([]byte, error) {
	authInfo := make([]byte, 16)
	_, err := io.ReadFull(r, authInfo)
	if err != nil {
		return nil, err
	}
	err = CheckEAuId(s.cmdKey[:], authInfo, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	return authInfo, nil
}

func (s *Session) ReadCommand(r io.Reader, authBuf []byte) (*Command, error) {
	headerBuf, err := OpenAeadHeader(r, s.cmdKey, authBuf)
	if err != nil {
		return nil, err
	}

	cmd, err := NewCommandFromBuffer(headerBuf)
	if err != nil {
		return nil, err
	}

	if cmd.GetCommand() != CmdTCP {
		return nil, errors.New("invalid command, only tcp supported")
	}

	return cmd, nil
}

func (s *Session) WriteResponse(w io.Writer, cmd *Command) error {
	resp := NewResponse(0)
	resp.SetV(cmd.GetResponseAuthV())
	resp.SetOption(cmd.GetOption())

	key := cmd.GetResponseCipherKey()
	iv := cmd.GetResponseCipherIV()
	return SealAeadResponse(w, key, iv, resp.ResponseHeader[:])
}
