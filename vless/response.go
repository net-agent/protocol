package vless

import "io"

const (
	MinResponseSize = 2
	MaxResponseSize = 2 + 255
)

type Response struct {
	buf [MaxResponseSize]byte
}

func (resp *Response) ReadFrom(r io.Reader) (int64, error) {
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

	return readed, nil
}
