package vmess

import (
	"crypto/cipher"
	"io"
)

func NewSecurityWriter(raw io.Writer, stream cipher.Stream) *SecurityWriter {
	return &SecurityWriter{
		raw:       raw,
		stream:    stream,
		cipherBuf: make([]byte, 4*1024),
	}
}

type SecurityWriter struct {
	raw       io.Writer
	stream    cipher.Stream
	cipherBuf []byte
}

func (sw *SecurityWriter) Write(buf []byte) (int, error) {
	return WriteAll(sw.safeWriteFrame, buf, len(sw.cipherBuf))
}

func (sw *SecurityWriter) safeWriteFrame(buf []byte) error {
	copyN := copy(sw.cipherBuf, buf)
	sw.stream.XORKeyStream(sw.cipherBuf[:copyN], sw.cipherBuf[:copyN])
	_, err := sw.raw.Write(sw.cipherBuf[:copyN])
	return err
}

func NewSecurityReader(raw io.Reader, stream cipher.Stream) *SecurityReader {
	return &SecurityReader{
		raw:    raw,
		stream: stream,
	}
}

type SecurityReader struct {
	raw    io.Reader
	stream cipher.Stream
}

func (sr *SecurityReader) Read(buf []byte) (int, error) {
	n, err := sr.raw.Read(buf)
	sr.stream.XORKeyStream(buf[:n], buf[:n])
	return n, err
}
