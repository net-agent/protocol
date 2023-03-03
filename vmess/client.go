package vmess

import (
	"encoding/json"
	"fmt"
	"log"
	"net"

	"github.com/net-agent/protocol/utils"
)

func NewConfigFromBytes(buf []byte) (*Config, error) {
	config := NewConfig()

	err := json.Unmarshal(buf, &config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func NewConfig() *Config {
	return &Config{
		Security:  "auto", // default
		Transport: "auto", // default
	}
}

type Config struct {
	Version   byte   `json:"v"`
	Network   string `json:"net"`       // ws/wss/tcp
	Address   string `json:"add"`       // e.g. 127.0.0.1 / baidu.com
	Port      uint16 `json:"port"`      // e.g. 80/443/...
	Path      string `json:"path"`      // e.g. /download/abc
	Id        string `json:"id"`        // uuid
	Security  string `json:"security"`  // none/auto/aes-128-cfb/aes-128-gcm/chacha20-poly1305
	Transport string `json:"transport"` // stream/chunk/mask/padding
	Tls       string `json:"tls"`
}

type Client struct {
	dial    utils.Dialer
	userid  []byte
	cmdKey  [16]byte
	secType byte
	option  byte
}

func NewClientFromBytes(buf []byte) (*Client, error) {
	cfg, err := NewConfigFromBytes(buf)
	if err != nil {
		return nil, err
	}

	client := &Client{}
	err = client.parse(cfg)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (client *Client) parse(config *Config) error {
	var err error

	client.dial, err = utils.MakeDialer(config.Network, config.Address, config.Port, config.Path)
	if err != nil {
		return err
	}

	// 解析用户标识
	client.userid, err = utils.ParseUUID(config.Id)
	if err != nil {
		return err
	}
	copy(client.cmdKey[:], GenCmdKey(client.userid))

	// 解析加密方式
	switch config.Security {
	case "aes-128-cfb":
		client.secType = SecTypeAES128CFB
	case "aes-128-gcm":
		client.secType = SecTypeAES128GCM
	case "chacha20-poly1305":
		client.secType = SecTypeChaCha20Poly1305
	case "auto", "": // todo
		client.secType = SecTypeAES128GCM
	case "none":
		client.secType = SecTypeNone
	default:
		return fmt.Errorf("security='%v' not supported", config.Security)
	}

	// 解析传输Option参数
	switch config.Transport {
	case "stream":
		client.option = 0
		if (client.secType != SecTypeNone) && (client.secType != SecTypeAES128CFB) {
			return fmt.Errorf("invalid config pair, transport='%v' and security='%v'", config.Transport, config.Security)
		}
	case "chunk":
		client.option = OptionS
	case "mask":
		client.option = OptionS | OptionM
	case "padding", "auto", "":
		client.option = OptionS | OptionM | OptionP
		if (client.secType != SecTypeAES128GCM) && (client.secType != SecTypeChaCha20Poly1305) {
			return fmt.Errorf("invalid config pair, transport='%v' and security='%v'", config.Transport, config.Security)
		}
	default:
		return fmt.Errorf("transport='%v' not supported", config.Transport)
	}

	return nil
}

// 根据配置，创建与服务端的连接
func (client *Client) Dial(network string, addrType byte, addrData []byte, port uint16) (net.Conn, error) {
	raw, err := client.dial()
	if err != nil {
		log.Println("connect server failed: ", err)
		return nil, err
	}

	return client.Upgrade(raw, addrType, addrData, port), nil
}

func (client *Client) Upgrade(c net.Conn, addrType byte, addrData []byte, port uint16) net.Conn {
	return &ClientConn{
		Client: client,
		Conn:   c,
		command: NewCommand(
			CmdTCP,
			client.option,
			client.secType,
			addrType, addrData, port,
		),
	}
}
