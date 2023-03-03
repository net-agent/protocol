package vmess

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"math/rand"
)

const (
	OptionS = byte(0x01)
	OptionR = byte(0x02)
	OptionM = byte(0x04)
	OptionP = byte(0x08)

	SecTypeAES128CFB        = byte(1)
	SecTypeAES128GCM        = byte(3)
	SecTypeChaCha20Poly1305 = byte(4)
	SecTypeNone             = byte(5)
	SecTypeLegacy           = SecTypeAES128CFB

	CmdTCP = byte(0x01)
	CmdUDP = byte(0x02)

	AddressIPv4   = byte(0x01)
	AddressDomain = byte(0x02)
	AddressIPv6   = byte(0x03)
)

func NewCommandFromBuffer(buf []byte) (*Command, error) {
	cmd := &Command{}
	copy(cmd.CommandHeader[:], buf)

	if cmd.GetVersion() != 1 {
		return nil, errors.New("invalid version")
	}

	padStart := 0
	switch cmd.GetAddressType() {
	case AddressIPv4:
		cmd.addressData = buf[41:45]
		padStart = 45
	case AddressIPv6:
		cmd.addressData = buf[41:57]
		padStart = 57
	case AddressDomain:
		domainSize := int(buf[41])
		cmd.addressData = buf[42 : 42+domainSize]
		padStart = 42 + domainSize
	default:
		return nil, errors.New("invalid address type")
	}
	padEnd := padStart + int(cmd.GetPaddingSize())
	fnvSum := binary.BigEndian.Uint32(buf[padEnd : padEnd+4])

	if fnvSum != GenBufsFnvSum(buf[:padEnd]) {
		return nil, errors.New("invalid command checksum")
	}

	return cmd, nil
}

type Command struct {
	CommandHeader
	addressData []byte
	padding     []byte

	responseCipherKey []byte
	responseCipherIV  []byte
}

func (cmd *Command) GetResponseCipherKey() []byte {
	if cmd.responseCipherKey == nil {
		buf := sha256.Sum256(cmd.GetRequestCipherKey())
		cmd.responseCipherKey = buf[:16]
	}
	return cmd.responseCipherKey
}

func (cmd *Command) GetResponseCipherIV() []byte {
	if cmd.responseCipherIV == nil {
		buf := sha256.Sum256(cmd.GetRequestCipherIV())
		cmd.responseCipherIV = buf[:16]
	}
	return cmd.responseCipherIV
}

func NewCommand(command, option, secType byte, addressType byte, addressData []byte, port uint16) *Command {
	cmd := &Command{}

	// 先生成命令的随机部分
	randBuf := GenRandomBytes(16 + 16 + 1 + rand.Intn(16))
	requestIv := randBuf[0:16]
	requestKey := randBuf[16:32]
	responseAuthV := randBuf[32]
	paddingBuf := randBuf[33:]

	// 构建指令结构
	cmd.SetVersion(1)
	cmd.SetRequestCipherIV(requestIv)
	cmd.SetRequestCipherKey(requestKey)
	cmd.SetResponseAuthV(responseAuthV)
	cmd.SetOption(option)
	cmd.SetPadding(paddingBuf)
	cmd.SetSecType(secType)
	cmd.SetCommand(command)
	cmd.SetPort(port)
	cmd.SetAddress(addressType, addressData)

	return cmd
}

func (cmd *Command) SetAddress(addressType byte, addressData []byte) {
	cmd.SetAddressType(addressType)
	cmd.addressData = addressData
}

func (cmd *Command) SetPadding(padding []byte) {
	size := len(padding)
	if size > 0x0f {
		panic("padding size to long")
	}
	cmd.SetPaddingSize(byte(size))
	cmd.padding = padding
}

func (cmd *Command) WriteTo(w io.Writer) (written int64, retErr error) {
	var addressSize []byte
	if cmd.GetAddressType() == AddressDomain {
		addressSize = []byte{byte(len(cmd.addressData))}
	}

	checksum := GenBufsFnvSumBuf(nil,
		cmd.CommandHeader[:],
		addressSize,
		cmd.addressData,
		cmd.padding)

	n := int(0)
	bufs := [][]byte{cmd.CommandHeader[:], addressSize, cmd.addressData, cmd.padding, checksum}
	for index, buf := range bufs {
		if buf == nil {
			continue
		}
		n, retErr = w.Write(buf)
		written += int64(n)
		if retErr != nil {
			log.Printf("write command failed at bufs[%v]\n", index)
			return written, retErr
		}
	}

	return written, retErr
}

type CommandHeader [41]byte

func (h *CommandHeader) SetVersion(version byte)        { h[0] = version }
func (h *CommandHeader) SetRequestCipherIV(iv []byte)   { copy(h[1:17], iv[0:16]) }
func (h *CommandHeader) SetRequestCipherKey(key []byte) { copy(h[17:33], key[0:16]) }
func (h *CommandHeader) SetResponseAuthV(v byte)        { h[33] = v }
func (h *CommandHeader) SetOption(option byte)          { h[34] = option }
func (h *CommandHeader) SetPaddingSize(size byte)       { h[35] = (h[35] & 0x0F) | (size << 4) }
func (h *CommandHeader) SetSecType(t byte)              { h[35] = (h[35] & 0xF0) | (t & 0x0F) }
func (h *CommandHeader) SetReserve(d byte)              { h[36] = d }
func (h *CommandHeader) SetCommand(command byte)        { h[37] = command }
func (h *CommandHeader) SetPort(port uint16)            { binary.BigEndian.PutUint16(h[38:40], port) }
func (h *CommandHeader) SetAddressType(t byte)          { h[40] = t }

func (h *CommandHeader) GetVersion() byte            { return h[0] }
func (h *CommandHeader) GetRequestCipherIV() []byte  { return h[1:17] }
func (h *CommandHeader) GetRequestCipherKey() []byte { return h[17:33] }
func (h *CommandHeader) GetResponseAuthV() byte      { return h[33] }
func (h *CommandHeader) GetOption() byte             { return h[34] }
func (h *CommandHeader) GetPaddingSize() byte        { return h[35] >> 4 }
func (h *CommandHeader) GetSecType() byte            { return h[35] & 0x0F }
func (h *CommandHeader) GetCommand() byte            { return h[37] }
func (h *CommandHeader) GetPort() uint16             { return binary.BigEndian.Uint16(h[38:40]) }
func (h *CommandHeader) GetAddressType() byte        { return h[40] }

func (h *CommandHeader) HashOption(op byte) bool { return (h[34] & op) > 0 }
