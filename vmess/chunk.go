package vmess

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"

	"golang.org/x/crypto/chacha20poly1305"
)

const maxMetaSize = 2
const maxTagSize = 16
const maxFnvSize = 4
const MaxPadSize = 64
const MaxChunkSize = (1 << 14)
const MaxDataSize = MaxChunkSize - (maxMetaSize + maxTagSize + maxFnvSize + MaxPadSize)

// 基于Command的信息初始化Chunk
// 调用之前需要确保OptionS是出于启用状态
func NewChunkWithCommand(cmd *Command, isClient, isWriter bool) *Chunk {
	isServer := !isClient
	isReader := !isWriter
	c := NewChunk()

	// 是否已经启动：元数据混淆
	// 元数据混淆有两个级别：
	// 级别一：混淆长度信息 (OptionM)
	// 级别二：填充随机长度的随机数据 (OptionM|OptionP)
	if cmd.HashOption(OptionM) {
		// 客户端的写与服务端的读，是配对的
		if (isClient && isWriter) || (isServer && isReader) {
			c.EnableMask(cmd.GetRequestCipherIV()[:16], cmd.HashOption(OptionP))
		} else {
			c.EnableMask(cmd.GetResponseCipherIV()[:16], cmd.HashOption(OptionP))
		}
	}

	if cmd.GetSecType() == SecTypeAES128CFB {
		c.EnableFnvSum()
	} else {

		var makeAead func([]byte) (cipher.AEAD, error)
		var makeKey func(key []byte) []byte

		switch cmd.GetSecType() {
		case SecTypeAES128GCM:
			makeAead = GenAesGcmAead
			makeKey = func(key []byte) []byte { return key }
		case SecTypeChaCha20Poly1305:
			makeAead = chacha20poly1305.New
			makeKey = GenChaChaKey // chacha key 长度是32字节，需要扩充
		}

		if makeAead != nil {
			if isClient {
				if isWriter {
					c.encryptor = GenChunkEncryptor(makeAead, makeKey(cmd.GetRequestCipherKey()), cmd.GetRequestCipherIV())
				} else {
					c.decryptor = GenChunkDecryptor(makeAead, makeKey(cmd.GetResponseCipherKey()), cmd.GetResponseCipherIV())
				}
			}

			if isServer {
				if isWriter {
					c.encryptor = GenChunkEncryptor(makeAead, makeKey(cmd.GetResponseCipherKey()), cmd.GetResponseCipherIV())
				} else {
					c.decryptor = GenChunkDecryptor(makeAead, makeKey(cmd.GetRequestCipherKey()), cmd.GetRequestCipherIV())
				}
			}
		}
	}

	return c
}

func NewChunk() *Chunk {
	return &Chunk{
		bufs: &chunkBuffers{
			meta:    []byte{0, 0},
			padding: nil,
		},
	}
}

type Chunk struct {
	bufs *chunkBuffers

	mask, padding bool
	shaker        *Shaker

	encryptor ChunkEncryptor
	decryptor ChunkDecryptor
}
type chunkBuffers struct {
	meta    []byte // 2B
	fnvSum  []byte // 4B
	data    []byte
	padding []byte
}

// 启用元数据混淆
func (c *Chunk) EnableMask(shakeKey []byte, padding bool) *Chunk {
	c.shaker = NewShaker(shakeKey)
	c.mask = true
	if padding {
		c.padding = padding
		c.bufs.padding = make([]byte, MaxPadSize)[:0]
	}
	return c
}

// 启用数据前置fnv校验和
func (c *Chunk) EnableFnvSum() *Chunk {
	c.bufs.fnvSum = make([]byte, 4)
	return c
}

func (c *Chunk) Data() []byte  { return c.bufs.data }
func (c *Chunk) DataSize() int { return len(c.Data()) }

// 将数据块写入到制定Writer中
func (c *Chunk) WriteTo(w io.Writer) (int64, error) {
	var total int64
	var n int
	var err error

	for _, buf := range [][]byte{
		c.bufs.meta,
		c.bufs.fnvSum,
		c.bufs.data,
		c.bufs.padding,
	} {
		if len(buf) == 0 {
			continue
		}

		n, err = w.Write(buf)
		total += int64(n)
		if err != nil {
			return total, err
		}
	}

	return total, nil
}

// 载入数据，根据启用的选项决定bufs的结构
func (c *Chunk) SetData(data []byte) *Chunk {
	c.setMeta(data)
	c.setPadding()
	c.setFnvSum(data)

	// 填充实际数据
	if c.encryptor != nil {
		c.bufs.data = c.encryptor(data)
	} else {
		c.bufs.data = data
	}

	return c
}

// 设置meta信息
// * 不启用mask时，meta为数据长度L
// * 启用mask时，meta为(L ^ nextShakeUint16)
//
// * 正常情况下 L = len(data)
// * 启用aes-cfb情况下 L = len(data) + 4
// * 启用aes-gcm情况下 L = len(data) + 16
func (c *Chunk) setMeta(data []byte) {
	meta := uint16(len(data))
	if c.bufs.fnvSum != nil {
		meta += 4 // size of uint32
	}
	if c.encryptor != nil {
		meta += 16 // size of gcm tag
	}
	if c.mask {
		padSize := uint16(0)
		if c.padding {
			padSize = c.shaker.NextUint16() % MaxPadSize
			c.bufs.padding = c.bufs.padding[:padSize] // 重复使用padding的内存
			meta += padSize
		}
		mask := c.shaker.NextUint16()
		// log.Printf("encode: size=%v mask=%v pad=%v meta=%v\n", meta, mask, padSize, meta^mask)

		meta ^= mask
	}
	binary.BigEndian.PutUint16(c.bufs.meta, meta)
}

// 设置fnv校验和
// * 仅当加密方式为aes-cfb时启用
func (c *Chunk) setFnvSum(data []byte) {
	if c.bufs.fnvSum == nil {
		return
	}
	GenBufsFnvSumBuf(c.bufs.fnvSum[:0], data)
}

func (c *Chunk) setPadding() {
	if !c.mask || !c.padding {
		return
	}
	rand.Read(c.bufs.padding)
}

func (c *Chunk) ReadFrom(r io.Reader) (int64, error) {
	readed := int64(0)

	// 第一步：确定数据段的大小
	n, err := io.ReadFull(r, c.bufs.meta)
	readed += int64(n)
	if err != nil {
		return readed, err
	}
	dataSize, padSize := c.parseMeta()

	// 第二步：读取校验和字段（如果有）
	if c.bufs.fnvSum != nil {
		n, err = io.ReadFull(r, c.bufs.fnvSum)
		readed += int64(n)
		if err != nil {
			return readed, err
		}
	}

	// 第三步：读取剩余数据段（含数据部分和填充部分）
	payload := make([]byte, dataSize+padSize)
	n, err = io.ReadFull(r, payload)
	readed += int64(n)
	if err != nil {
		return readed, err
	}
	c.bufs.data = payload[:dataSize]
	c.bufs.padding = payload[dataSize:]

	// 第四步：数据解密（如果有）
	if c.decryptor != nil {
		c.bufs.data, err = c.decryptor(c.bufs.data)
		if err != nil {
			return readed, err
		}
	}

	// 第五步：数据校验（如果有）
	if c.bufs.fnvSum != nil {
		recvsum := binary.BigEndian.Uint32(c.bufs.fnvSum)
		calcsum := GenBufsFnvSum(nil, c.bufs.data)
		if recvsum != calcsum {
			return readed, errors.New("checksum not match")
		}
	}

	return readed, nil
}

func (c *Chunk) parseMeta() (dataSize, padSize uint16) {
	meta := binary.BigEndian.Uint16(c.bufs.meta[:2])
	dataSize = meta

	if c.mask {
		if c.padding {
			padSize = c.shaker.NextUint16() % MaxPadSize
		}
		mask := c.shaker.NextUint16()

		total := meta ^ mask
		dataSize = total - padSize
	}

	if c.bufs.fnvSum != nil {
		dataSize -= 4
	}

	return
}
