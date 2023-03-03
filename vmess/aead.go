package vmess

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	mrand "math/rand"
	"time"
)

func init() {
	mrand.Seed(time.Now().UnixNano())
}

const (
	aeadTagSize          = int(16)
	AeadKeyOfHeaderLen   = "VMess Header AEAD Key_Length"
	AeadNonceOfHeaderLen = "VMess Header AEAD Nonce_Length"
	AeadKeyOfHeaderBuf   = "VMess Header AEAD Key"
	AeadNonceOfHeaderBuf = "VMess Header AEAD Nonce"
	AeadKeyOfRespLen     = "AEAD Resp Header Len Key"
	AeadNonceOfRespLen   = "AEAD Resp Header Len IV"
	AeadKeyOfRespBuf     = "AEAD Resp Header Key"
	AeadNonceOfRespBuf   = "AEAD Resp Header IV"
)

func SealAeadHeader(w io.Writer, cmdKey [16]byte, plainHeader []byte) error {
	// EAuID
	authidBuf, err := GenEAuId(cmdKey[:], time.Now().Unix(), mrand.Int())
	if err != nil {
		return err
	}
	authid := string(authidBuf)

	// Nonce
	nonceBuf := make([]byte, 8)
	_, err = io.ReadFull(rand.Reader, nonceBuf)
	if err != nil {
		return err
	}
	nonce := string(nonceBuf)

	// ELength
	plainLenBuf := []byte{0, 0}
	binary.BigEndian.PutUint16(plainLenBuf, uint16(len(plainHeader)))
	encKey := GenKDF16Key(cmdKey[:], AeadKeyOfHeaderLen, authid, nonce)
	encNonce := GenKDFKey(cmdKey[:], AeadNonceOfHeaderLen, authid, nonce)[:12]
	lenBuf, err := AesGcmEncrypt(encKey, encNonce, plainLenBuf, authidBuf)
	if err != nil {
		return err
	}

	// EHeader
	encKey = GenKDF16Key(cmdKey[:], AeadKeyOfHeaderBuf, authid, nonce)
	encNonce = GenKDFKey(cmdKey[:], AeadNonceOfHeaderBuf, authid, nonce)[:12]
	headerBuf, err := AesGcmEncrypt(encKey, encNonce, plainHeader, authidBuf)
	if err != nil {
		return err
	}

	// merge
	for _, buf := range [][]byte{authidBuf, lenBuf, nonceBuf, headerBuf} {
		_, err = w.Write(buf)
		if err != nil {
			return err
		}
	}

	return nil
}

func OpenEAuId(r io.Reader, cmdKey [16]byte) ([]byte, error) {
	// 先读取[EAuId][ELength][Nonce 8B]
	// 长度为：16 + (2+16) + 8
	authidBuf := make([]byte, 16)
	_, err := io.ReadFull(r, authidBuf)
	if err != nil {
		return nil, err
	}

	// 校验EAuId的正确性
	var fixedAuthidBuf [16]byte
	copy(fixedAuthidBuf[:], authidBuf)
	err = CheckEAuId(cmdKey[:], fixedAuthidBuf[:], time.Now().Unix())
	if err != nil {
		return nil, err
	}
	return authidBuf, nil
}

func OpenAeadHeader(r io.Reader, cmdKey [16]byte, authidBuf []byte) ([]byte, error) {
	buf := make([]byte, 2+16+8)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}
	// 读取Nonce信息
	nonceBuf := buf[18:]
	nonce := string(nonceBuf)

	// 读取ELenght，获取实际大小
	authid := string(authidBuf)
	lenBuf := buf[0:18]
	decKey := GenKDF16Key(cmdKey[:], AeadKeyOfHeaderLen, authid, nonce)
	decNonce := GenKDFKey(cmdKey[:], AeadNonceOfHeaderLen, authid, nonce)[:12]
	plainLenBuf, err := AesGcmDecrypt(decKey, decNonce, lenBuf, authidBuf)
	if err != nil {
		return nil, err
	}

	headerLen := int(binary.BigEndian.Uint16(plainLenBuf[:2])) + aeadTagSize

	// 读取Header
	headerBuf := make([]byte, headerLen)
	_, err = io.ReadFull(r, headerBuf)
	if err != nil {
		return nil, err
	}

	decKey = GenKDF16Key(cmdKey[:], AeadKeyOfHeaderBuf, authid, nonce)
	decNonce = GenKDFKey(cmdKey[:], AeadNonceOfHeaderBuf, authid, nonce)[:12]
	return AesGcmDecrypt(decKey, decNonce, headerBuf, authidBuf)
}

func SealAeadResponse(w io.Writer, key, iv []byte, plainData []byte) error {

	// [ELength 18B][EResponse]

	// ELength
	plainLenBuf := []byte{0, 0}
	binary.BigEndian.PutUint16(plainLenBuf, uint16(len(plainData)))
	encKey := GenKDF16Key(key, AeadKeyOfRespLen)
	encNonce := GenKDFKey(iv, AeadNonceOfRespLen)[:12]
	lenBuf, err := AesGcmEncrypt(encKey, encNonce, plainLenBuf, nil)
	if err != nil {
		return err
	}

	// EResponse
	encKey = GenKDF16Key(key, AeadKeyOfRespBuf)
	encNonce = GenKDFKey(iv, AeadNonceOfRespBuf)[:12]
	dataBuf, err := AesGcmEncrypt(encKey, encNonce, plainData, nil)
	if err != nil {
		return err
	}

	for _, buf := range [][]byte{lenBuf, dataBuf} {
		_, err = w.Write(buf)
		if err != nil {
			return err
		}
	}

	return nil
}

func OpenAeadResponse(r io.Reader, key, iv []byte) ([]byte, error) {
	buf := make([]byte, 2+16)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}

	// 读取ELength明文
	decKey := GenKDF16Key(key, AeadKeyOfRespLen)
	decNonce := GenKDFKey(iv, AeadNonceOfRespLen)[:12]
	plainLenBuf, err := AesGcmDecrypt(decKey, decNonce, buf, nil)
	if err != nil {
		return nil, err
	}

	respLen := int(binary.BigEndian.Uint16(plainLenBuf)) + aeadTagSize

	// 读取EResponse明文
	buf = make([]byte, respLen)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}
	decKey = GenKDF16Key(key, AeadKeyOfRespBuf)
	decNonce = GenKDFKey(iv, AeadNonceOfRespBuf)[:12]
	return AesGcmDecrypt(decKey, decNonce, buf, nil)
}

type AeadCreator func([]byte) (cipher.AEAD, error)
type ChunkEncryptor func([]byte) []byte
type ChunkDecryptor func([]byte) ([]byte, error)

func GenChunkEncryptor(createAead AeadCreator, key, iv []byte) ChunkEncryptor {
	aead, err := createAead(key)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, aead.NonceSize())
	copy(nonce, iv)

	count := uint16(0)
	cache := []byte{}

	return func(plain []byte) []byte {
		binary.BigEndian.PutUint16(nonce[:2], count)
		count++
		data := aead.Seal(cache[:0], nonce, plain, nil)
		cache = data[:0]
		return data
	}
}

func GenChunkDecryptor(createAead AeadCreator, key, iv []byte) ChunkDecryptor {
	aead, err := createAead(key)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, aead.NonceSize())
	copy(nonce, iv)

	count := uint16(0)
	cache := []byte{}

	return func(ciphertext []byte) ([]byte, error) {
		binary.BigEndian.PutUint16(nonce[:2], count)
		count++
		plain, err := aead.Open(cache, nonce, ciphertext, nil)
		if err != nil {
			return nil, err
		}
		cache = plain[:0]
		return plain, nil
	}
}
