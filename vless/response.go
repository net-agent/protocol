package vless

import "io"

const (
	MinResponseSize = 2
	MaxResponseSize = 2 + 255
)

func NewResponse(version byte, attach []byte) *Response {
	resp := &Response{}
	resp.buf[0] = version
	resp.buf[1] = byte(len(attach))
	resp.size = 2
	if resp.buf[1] > 0 {
		n := copy(resp.buf[2:], attach)
		resp.size += n
	}
	return resp
}

type Response struct {
	buf  [MaxResponseSize]byte
	size int
}

func (resp *Response) Bytes() []byte { return resp.buf[:resp.size] }

func (resp *Response) ReadFrom(r io.Reader) (int64, error) {
	resp.size = 0
	readed := int64(0)
	n, err := io.ReadFull(r, resp.buf[:MinResponseSize])
	readed += int64(n)
	if err != nil {
		return readed, err
	}

	tailSize := int(resp.buf[1])
	if tailSize > 0 {
		n, err = io.ReadFull(r, resp.buf[2:2+tailSize])
		readed += int64(n)
		if err != nil {
			return readed, err
		}
	}

	resp.size = int(readed)
	return readed, nil
}

func (resp *Response) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(resp.Bytes())
	return int64(n), err
}
