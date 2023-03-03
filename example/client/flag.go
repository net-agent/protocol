package main

import (
	"encoding/json"
	"flag"
)

type ProxyConfig struct {
	Protocol  string `json:"protocol"`
	Version   byte   `json:"v"`
	Network   string `json:"net"`
	Address   string `json:"add"`
	Port      uint16 `json:"port"`
	Path      string `json:"path"`
	Id        string `json:"id"`
	Security  string `json:"security"`  // none/auto/aes-128-cfb/aes-128-gcm/chacha20-poly1305
	Transport string `json:"transport"` // stream/chunk/mask/padding
}

func (p *ProxyConfig) Bytes() []byte {
	buf, _ := json.Marshal(p)
	return buf
}

func ParseFlag() (string, *ProxyConfig, error) {
	var listen string
	var cfg = &ProxyConfig{}
	var port int
	flag.StringVar(&listen, "l", "", "local listen address, e.g. 'localhost:1234'")
	flag.StringVar(&cfg.Protocol, "protocol", "vmess", "protocol: vmess/vless")
	flag.StringVar(&cfg.Network, "net", "tcp", "server network, options: tcp/ws")
	flag.StringVar(&cfg.Address, "add", "", "server address, e.g. 'localhost'")
	flag.IntVar(&port, "port", 0, "server port, e.g. 80")
	flag.StringVar(&cfg.Path, "path", "/", "path of websocket")
	flag.StringVar(&cfg.Id, "id", "", "uuid")
	flag.StringVar(&cfg.Security, "security", "", "vmess only, options: none/auto/aes-128-cfb/aes-128-gcm/chacha20-poly1305")
	flag.StringVar(&cfg.Transport, "transport", "", "vmess only, options: stream/chunk/mask/padding")

	flag.Parse()
	cfg.Port = uint16(port)

	if listen == "" || cfg.Address == "" || cfg.Port == 0 || cfg.Id == "" {
		flag.Usage()
		panic("parse failed")
	}

	return listen, cfg, nil
}
