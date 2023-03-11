package vmess

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"hash/crc32"
	"hash/fnv"
	"log"
	"math/rand"
)

// 生成userid的16位hash值，使用MD5，并且加盐
func GenCmdKey(userid []byte) []byte {
	return GenBufsMd5(userid, []byte("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
}

type hashMaker func() hash.Hash

// 使用KDF算法扩展key产生新的key
func GenKDFKey(key []byte, path ...string) []byte {
	wrap := func(h hashMaker, key []byte) hashMaker {
		return func() hash.Hash { return hmac.New(h, key) }
	}

	hm := wrap(sha256.New, []byte("VMess AEAD KDF"))
	for _, p := range path {
		hm = wrap(hm, []byte(p))
	}

	h := hm()
	h.Write(key)

	return h.Sum(nil)
}
func GenKDF16Key(key []byte, path ...string) []byte {
	return GenKDFKey(key, path...)[:16]
}

// 生成EAuId
// 结构：[timestamp 8B][rand 4B][checksum 4B]
func GenEAuId(cmdKey []byte, timestamp int64, rnd int) ([]byte, error) {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:8], uint64(timestamp))
	binary.BigEndian.PutUint32(buf[8:12], uint32(rnd))
	csum := crc32.ChecksumIEEE(buf[0:12])
	binary.BigEndian.PutUint32(buf[12:16], csum)

	err := AesEncryptOverwrite(GenKDF16Key(cmdKey, "AES Auth ID Encryption"), buf)
	if err != nil {
		log.Panic("GenEAuId failed: ", err)
	}
	return buf, nil
}

// 校验EAuId合法性
func CheckEAuId(cmdKey []byte, authInfo []byte, timestamp1 int64) error {
	data := make([]byte, len(authInfo))
	copy(data, authInfo)
	err := AesDecryptOverwrite(GenKDF16Key(cmdKey, "AES Auth ID Encryption"), data[:16])
	if err != nil {
		return err
	}
	csum1 := crc32.ChecksumIEEE(data[0:12])
	csum2 := binary.BigEndian.Uint32(data[12:16])
	if csum1 != csum2 {
		return errors.New("checksum not match")
	}

	timestamp2 := int64(binary.BigEndian.Uint64(data[0:8]))
	delta := timestamp1 - timestamp2
	if delta < 120 && delta > -120 {
		return nil
	}
	return errors.New("invalid timestamp")
}

func AesGcmEncrypt(key, nonce, plain, additional []byte) ([]byte, error) {
	aead, err := GenAesGcmAead(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plain, additional), nil
}

func AesGcmDecrypt(key, nonce, data, addtional []byte) ([]byte, error) {
	aead, err := GenAesGcmAead(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, data, addtional)
}

func GenAesGcmAead(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead, nil
}

// 使用AES对内容进行加密，加密后的密文会覆盖原数据
func AesEncryptOverwrite(key []byte, plain []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	block.Encrypt(plain, plain)
	return nil
}

// 使用AES对内容进行解密，解密后的明文会覆盖原数据
func AesDecryptOverwrite(key []byte, encData []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	block.Decrypt(encData, encData)
	return nil
}

func GenAuthData(userid []byte, utcTimeBuf []byte) []byte {
	h := hmac.New(md5.New, userid)
	h.Write(utcTimeBuf)
	return h.Sum(nil)
}

func GenUTCTimeBytes(t int64, delta int) []byte {
	if delta > 0 {
		n := rand.Intn(delta*2) - delta
		t = t + int64(n)
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(t))
	return buf
}

func GenRandomBytes(size int) []byte {
	if size == 0 {
		return nil
	}

	buf := make([]byte, size)
	rand.Read(buf)

	return buf
}

func NewAesCfbEncStream(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBEncrypter(block, iv), nil
}

func NewAesCfbDecStream(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBDecrypter(block, iv), nil
}

func GenBufsMd5(bufs ...[]byte) []byte {
	h := md5.New()
	for _, buf := range bufs {
		_, err := h.Write(buf)
		if err != nil {
			panic(err)
		}
	}
	return h.Sum(nil)
}

func GenBufsFnvSum(bufs ...[]byte) uint32 {
	h := fnv.New32a()
	for _, buf := range bufs {
		_, err := h.Write(buf)
		if err != nil {
			panic(err)
		}
	}
	return h.Sum32()
}

func GenBufsFnvSumBuf(dist []byte, bufs ...[]byte) []byte {
	h := fnv.New32a()
	for _, buf := range bufs {
		_, err := h.Write(buf)
		if err != nil {
			panic(err)
		}
	}
	return h.Sum(dist)
}

func GenChaChaKey(key []byte) []byte {
	resp := make([]byte, 32)

	m1 := md5.Sum(key)
	copy(resp[:16], m1[:])
	m2 := md5.Sum(m1[:])
	copy(resp[16:], m2[:])

	return resp
}

type WriteFrameHandler func([]byte) error

func WriteAll(wf WriteFrameHandler, buf []byte, sliceSize int) (nn int, ee error) {
	var p []byte
	for {
		p = buf
		if len(p) > sliceSize {
			p = buf[:sliceSize]
			buf = buf[sliceSize:]
		} else {
			p = buf
			buf = nil
		}

		ee = wf(p)
		nn += len(p)

		if ee != nil {
			return nn, ee
		}

		if len(buf) == 0 {
			return nn, nil
		}
	}
}
