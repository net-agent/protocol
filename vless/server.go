package vless

import (
	"bytes"
	"errors"
	"log"
	"net"

	"github.com/net-agent/protocol/utils"
)

func NewSession(id string) (*Session, error) {
	sess := &Session{}
	uuid, err := utils.ParseUUID(id)
	if err != nil {
		return nil, err
	}
	copy(sess.uuid[:], uuid)
	return sess, nil
}

type Session struct {
	uuid [16]byte
}

func (s *Session) Process(c net.Conn) error {
	defer c.Close()
	var err error

	cmd := &Command{}
	_, err = cmd.ReadFrom(c)
	if err != nil {
		return err
	}
	if !bytes.Equal(cmd.GetUUID(), s.uuid[:]) {
		return errors.New("invalid uuid")
	}

	t := utils.NewAddrType(utils.ProtoVless, cmd.GetAddressType())
	addr, err := utils.AddrString(t, cmd.GetAddressData(), cmd.GetPort())
	if err != nil {
		return err
	}

	target, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("dial failed:  %v\n", addr)
		return err
	}
	defer target.Close()
	log.Printf("dial success: %v\n", addr)

	_, err = NewResponse(cmd.Version(), nil).WriteTo(c)
	if err != nil {
		return err
	}

	rn, wn, err := utils.LinkReadWriter(c, target)
	log.Printf("closed: %v, %v readed, %v written, err=%v\n", addr, rn, wn, err)
	return err
}
