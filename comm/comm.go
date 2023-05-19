package comm

import (
	"encoding/json"
	"time"
)

// 一些公用配置
var (
	MaxMessageLength          = 4096
	WsConnExchangeReadTimeout = time.Second * 10
	Token                     = "random_string_as_token"
	WssHandshakeTimeout       = time.Second * 10
)

var (
	IPV4   = 1
	Domain = 2
	IPV6   = 3
)

var (
	StatusConnected  = "OK"
	StatusAuthFailed = "AuthFailed"
	// 各类问题比如:
	//	1. 客户端传过去的域名不能正确解析
	//	2. 客户端传垃圾值
	// 	3. 服务端那里无法正确建立tcp连接
	//	4. TODO: 待归纳
	StatusUnexpected = "Unexpected"
)

var (
	RequestTCP = 1
	RequestUDP = 3
)

var (
	PacketTypeTransport = 1
	PacketTypeHeartbeat = 2
)

type PacketHeader struct {
	Type int `json:"type"`
}

type PacketHeartbeat struct {
	PacketHeader
}

func (ph *PacketHeartbeat) MustToBytes() []byte {
	b, err := json.Marshal(ph)
	if err != nil {
		panic(err)
	}
	return b
}

// 这个字段的data必须为非nil
type PacketTransport struct {
	PacketHeader
	Data *string `json:"data"`
}

func (pt *PacketTransport) MustToBytes() []byte {
	b, err := json.Marshal(pt)
	if err != nil {
		panic(err)
	}
	return b
}

func ParsePacketType(bs []byte) interface{} {
	var ph PacketHeader
	if err := json.Unmarshal(bs, &ph); err != nil {
		return nil
	}

	switch ph.Type {
	case PacketTypeHeartbeat:
		return &PacketHeartbeat{PacketHeader: PacketHeader{Type: PacketTypeHeartbeat}}
	case PacketTypeTransport:
		var pt PacketTransport
		json.Unmarshal(bs, &pt)
		if pt.Data != nil {
			return &pt
		}
	}

	return nil
}
