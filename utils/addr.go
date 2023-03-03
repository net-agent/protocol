package utils

import (
	"fmt"
	"net"
)

type ProtocolType byte
type AddrType byte

const (
	ProtoSocksV5 ProtocolType = 0
	ProtoVmess   ProtocolType = 1
	ProtoVless   ProtocolType = 2
)

const (
	AddrIPv4    AddrType = 0
	AddrIPv6    AddrType = 4
	AddrDomain  AddrType = 3
	AddrUnknown AddrType = 99

	SocksV5AddrIPv4   AddrType = 0
	SocksV5AddrIPv6   AddrType = 4
	SocksV5AddrDomain AddrType = 3

	VmessAddrIPv4   byte = 1
	VmessAddrIPv6   byte = 3
	VmessAddrDomain byte = 2

	VlessAddrIPv4   byte = 0
	VlessAddrIPv6   byte = 1
	VlessAddrDomain byte = 2
)

func NewAddrType(protocol ProtocolType, val byte) AddrType {
	switch protocol {
	case ProtoSocksV5:
		return AddrType(val)
	case ProtoVmess:
		switch val {
		case VmessAddrIPv4:
			return AddrIPv4
		case VmessAddrIPv6:
			return AddrIPv6
		case VmessAddrDomain:
			return AddrDomain
		default:
			return AddrUnknown
		}
	case ProtoVless:
		switch val {
		case VlessAddrIPv4:
			return AddrIPv4
		case VlessAddrIPv6:
			return AddrIPv6
		case VlessAddrDomain:
			return AddrDomain
		default:
			return AddrUnknown
		}
	default:
		return AddrUnknown
	}
}

func (t AddrType) String() string {
	switch t {
	case AddrIPv4:
		return "IPv4"
	case AddrIPv6:
		return "IPv6"
	case AddrDomain:
		return "Domain"
	default:
		return "Unknown"
	}
}

func (t AddrType) Byte(protocol ProtocolType) byte {
	switch protocol {
	case ProtoSocksV5:
		return byte(t)
	case ProtoVmess:
		switch t {
		case AddrIPv4:
			return VmessAddrIPv4
		case AddrIPv6:
			return VmessAddrIPv6
		case AddrDomain:
			return VmessAddrDomain
		}
	case ProtoVless:
		switch t {
		case AddrIPv4:
			return VlessAddrIPv4
		case AddrIPv6:
			return VlessAddrIPv6
		case AddrDomain:
			return VlessAddrDomain
		}
	}
	return byte(AddrUnknown)
}

func AddrString(t AddrType, addrData []byte, port uint16) string {
	switch t {
	case AddrIPv4, AddrIPv6:
		return fmt.Sprintf("%v:%v", net.IP(addrData).String(), port)
	case AddrDomain:
		return fmt.Sprintf("%v:%v", string(addrData), port)
	default:
		return "invalid_address"
	}
}
