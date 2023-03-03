package vless

import (
	"encoding/json"
	"log"
	"net"

	"github.com/net-agent/protocol/utils"
)

type Config struct {
	Version byte   `json:"v"`
	Network string `json:"net"`
	Address string `json:"add"`
	Port    uint16 `json:"port"`
	Path    string `json:"path"`
	Id      string `json:"id"`
}

type Client struct {
	dial   utils.Dialer
	userid []byte
}

// 解析JSON配置，初始化本地客户端
func NewClientFromBytes(buf []byte) (*Client, error) {
	cfg := &Config{}
	err := json.Unmarshal(buf, cfg)
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

	client.userid, err = utils.ParseUUID(config.Id)

	return err
}

func (client *Client) Dial(network string, addrType byte, addrData []byte, port uint16) (net.Conn, error) {
	raw, err := client.dial()
	if err != nil {
		log.Println("connect server failed:", err)
		return nil, err
	}

	return client.upgrade(raw, addrType, addrData, port), nil
}

func (client *Client) upgrade(c net.Conn, addrType byte, addrData []byte, port uint16) net.Conn {
	return &ClientConn{
		Client:  client,
		Conn:    c,
		command: NewCommand(client.userid, CommandTCP, addrType, addrData, port),
		resp:    &Response{},
	}
}
