package vmess

import (
	"errors"
	"io"
	"log"
)

func NewResponse(responseAuthV byte) *Response {
	return &Response{responseAuthV: responseAuthV}
}

type Response struct {
	ResponseHeader
	responseAuthV byte
}

func (resp *Response) ReadFrom(r io.Reader) (readed int64, retErr error) {
	var n int
	n, retErr = io.ReadFull(r, resp.ResponseHeader[:])
	readed += int64(n)
	if retErr != nil {
		return readed, retErr
	}

	if resp.GetV() != resp.responseAuthV {
		return readed, errors.New("respAuthV not match")
	}
	// if resp.GetOption() != 0 {
	// 	return readed, errors.New("option is not 0")
	// }
	cmdSize := resp.GetCommandSize()
	command := make([]byte, cmdSize) // 动态端口指令？
	n, retErr = io.ReadFull(r, command)
	readed += int64(n)
	if retErr != nil {
		return readed, retErr
	}
	if resp.GetCommandType() == 1 {
		log.Println("dynamic port command accept.")
	}

	return readed, nil
}

type ResponseHeader [4]byte

func (h *ResponseHeader) SetV(v byte)           { h[0] = v }
func (h *ResponseHeader) SetOption(option byte) { h[1] = option }
func (h *ResponseHeader) SetCommand()           { h[2] = 0; h[3] = 0 }

func (h *ResponseHeader) GetV() byte           { return h[0] }
func (h *ResponseHeader) GetOption() byte      { return h[1] }
func (h *ResponseHeader) GetCommandType() byte { return h[2] }
func (h *ResponseHeader) GetCommandSize() byte { return h[3] }
