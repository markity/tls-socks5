package main

import (
	"log"
	"net"
	"net/http"
	"net/netip"
	"tls-socks5/comm"

	"github.com/gorilla/websocket"
)

var Upgrader = websocket.Upgrader{
	HandshakeTimeout: comm.WssHandshakeTimeout,
	// buffer的大小让库自行选择
	ReadBufferSize:    0,
	WriteBufferSize:   0,
	CheckOrigin:       nil,
	Subprotocols:      []string{"wsproxy"},
	WriteBufferPool:   nil,
	Error:             nil,
	EnableCompression: false,
}

/*
extraHeader.Set("Wsproxy-Token", comm.Token)             // 密钥
extraHeader.Set("Wsproxy-Protocol", requestProtocolType) // tcp或udp
extraHeader.Set("Wsproxy-Addr-Type", dstAddrType)        // ipv4 ipv6或domain
extraHeader.Set("Wsproxy-Addr", string(dstAddrBytes))    // 地址, 根据Wsproxy-Addr-Type来
*/
func HandlerFunc(w http.ResponseWriter, r *http.Request) {
	// 进行一系列检查
	if token := w.Header().Get("Wsproxy-Token"); token != comm.Token {
		header := http.Header{}
		header.Set("Status", comm.StatusAuthFailed)
		// 忽略错误
		conn, _ := Upgrader.Upgrade(w, r, header)
		conn.Close()
		return
	}

	if protocol := w.Header().Get("Wsproxy-Protocol"); protocol != "tcp" && protocol != "udp" {
		header := http.Header{}
		header.Set("Status", comm.StatusUnexpected)
		conn, _ := Upgrader.Upgrade(w, r, header)
		conn.Close()
		return
	}

	ip := w.Header().Get("Wsproxy-Addr")
	switch w.Header().Get("Wsproxy-Addr-Type") {
	case "ipv4":
		addr, err := netip.ParseAddr(ip)
		if err != nil || !addr.Is4() {
			header := http.Header{}
			header.Set("Status", comm.StatusUnexpected)
			conn, _ := Upgrader.Upgrade(w, r, header)
			conn.Close()
			return
		}
	case "ipv6":
		addr, err := netip.ParseAddr(ip)
		if err != nil || !addr.Is6() {
			header := http.Header{}
			header.Set("Status", comm.StatusUnexpected)
			conn, _ := Upgrader.Upgrade(w, r, header)
			conn.Close()
			return
		}
	case "domain":
		net.Lookupho(ip)
	}

	conn, err := Upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("failed to upgrade a connection from %v: %v\n", r.Host, err)
		return
	}

	conn.Close()

}
