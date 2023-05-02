package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"tls-socks5/comm"

	"github.com/gorilla/websocket"
)

func init() {
	// 这里的握手包括tcp握手+wss握手
	websocket.DefaultDialer.HandshakeTimeout = WssHandshakeTimeout
	// 这么做的目的是如果不是权威机构签发的证书也能通过
	websocket.DefaultDialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: false}
}

func main() {
	tcpListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: LocalSocks5ServerPort})
	if err != nil {
		log.Fatalf("failed to listen tcp: %v\n", err)
	}

	// 循环接收连接, 比如浏览器, 一些应用程序都会连接本地socks5服务器
	for {
		tcpConn, err := tcpListener.AcceptTCP()
		if err != nil {
			// 临时错误, continue重试
			if err.(*net.OpError).Temporary() {
				log.Printf("accept tcp connection, temporay error, continuing: %v\n", err)
				continue
			} else {
				// 严重错误, simply 退出
				log.Fatalf("failed to accept tcp connection: %v\n", err)
			}
		}

		go func() {
			defer tcpConn.Close()

			/*
				客户端发来请求
				+----+----------+----------+
				|VER | NMETHODS | METHODS  |
				+----+----------+----------+
				| 1  |    1     | 1 to 255 |
				+----+----------+----------+

				服务端选择一个方法:
				+----+--------+
				|VER | METHOD |
				+----+--------+
				| 1  |   1    |
				+----+--------+
			*/

			// 拿version和nMethods
			var verAndNMethods []byte = make([]byte, 2)
			_, err := io.ReadFull(tcpConn, verAndNMethods)
			if err != nil {
				log.Printf("auth stage: unexpected read error when reading version and nMethods, quiting handler goroutine: %v\n", err)
				return
			}
			version, nMethods := int(verAndNMethods[0]), int(verAndNMethods[1])
			if version != 5 {
				log.Printf("auth stage: unsupported protocol version, quiting handler goroutine: %v\n", err)
				return
			}
			if nMethods == 0 {
				log.Printf("auth stage: protocol error: nMethods is 0, which is impossible, quiting handler goroutine\n")
				return
			}

			var methodsSupported []byte = make([]byte, nMethods)
			_, err = io.ReadFull(tcpConn, methodsSupported)
			if err != nil {
				log.Printf("auth stage: unexpected read error when reading methodsSupoorted, quiting handler goroutine: %v\n", err)
				return
			}
			var is0x00InMethodsSupported bool = false
			for _, v := range methodsSupported {
				if v == 0x00 {
					is0x00InMethodsSupported = true
					break
				}
			}
			// 不支持0x00方法, 那么就写入0x05, 0xFF来拒绝服务, 之后直接关闭连接
			if !is0x00InMethodsSupported {
				log.Printf("auth stage: client does not support 0x00(NO AUTHENTICATION REQUIRED) method, quiting handler goroutine: %v\n", err)
				_, err := tcpConn.Write([]byte{0x05, 0xFF})
				if err != nil {
					log.Printf("auth stage: write tcp connetion(to answer 0x05 0xFF to deny service, because client does not support 0x00 error) error, quiting handler goroutine: %v\n", err)
				}
				return
			}

			// auth 阶段的收尾阶段, 选择的是0x00, 无认证
			_, err = tcpConn.Write([]byte{0x05, 0x00})
			if err != nil {
				log.Printf("auth stage: write tcp connetion(to answer 0x05 0x00 to accept service) error, quiting handler goroutine: %v\n", err)
				return
			}

			// 下一阶段开始, 请求阶段, 拿取cmd
			/*
				client:
				+----+-----+-------+------+----------+----------+
				|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
				+----+-----+-------+------+----------+----------+
				| 1  |  1  | X'00' |  1   | Variable |    2     |
				+----+-----+-------+------+----------+----------+

				cmd:
				0x01表示CONNECT请求
				0x02表示BIND请求
				0x03表示UDP转发


				server:
				+----+-----+-------+------+----------+----------+
				|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
				+----+-----+-------+------+----------+----------+
				| 1  |  1  | X'00' |  1   | Variable |    2     |
				+----+-----+-------+------+----------+----------+

				rep:
				X’00’ succeeded
				X’01’ general SOCKS server failure
				X’02’ connection not allowed by ruleset
				X’03’ Network unreachable
				X’04’ Host unreachable
				X’05’ Connection refused
				X’06’ TTL expired
				X’07’ Command not supported
				X’08’ Address type not supported
				X’09’ to X’FF’ unassigned

			*/

			var verCmdRsvAtyp []byte = make([]byte, 4)
			_, err = io.ReadFull(tcpConn, verCmdRsvAtyp)
			if err != nil {
				log.Printf("request stage: unexpeceted read error, quiting handler goroutine: %v\n", err)
				return
			}
			version, cmd, rsv, atyp := int(verCmdRsvAtyp[0]), int(verCmdRsvAtyp[1]), int(verCmdRsvAtyp[2]), int(verCmdRsvAtyp[3])
			if verCmdRsvAtyp[0] != 5 {
				log.Printf("request stage: unexpeceted version(%v), quiting handler goroutine: %v\n", version, err)
				return
			}
			if cmd != 0 && cmd != 1 && cmd != 3 {
				log.Printf("request stage: protocol error, unkonwn cmd(%v), quiting handler goroutine\n", cmd)
				return
			}
			// 目前只支持connect和udp命令
			var requestProtocolType string
			switch cmd {
			case comm.RequestTCP:
				requestProtocolType = "tcp"
			case comm.RequestUDP:
				requestProtocolType = "udp"
			default:
				log.Printf("request stage: now noly cmd 1(tcp) and 3(udp) is supported, but cmd received %v, quiting handler goroutine\n", cmd)
				// 出错时, addr为0, port为0即可, atyp无所谓了, 这里写成0(TODO: 是否可以?)
				_, err := tcpConn.Write([]byte{0x05, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00})
				if err != nil {
					log.Printf("request stage: write tcp connetion(to answer 0x05 0x07 to deny service, because server does not support protocol expect for CONNECT) error, quiting handler goroutine: %v\n", err)
				}
				return
			}
			if rsv != 0 {
				log.Printf("request stage: unexpeceted rsv(%v), quiting handler goroutine: %v\n", rsv, err)
				return
			}
			// 1: ipv4 2: domain 3: ipv6
			// ipv4: 4字节
			// ipv6: 16字节
			// domain: 先来一个字节表示域名长度n, 后面n个字节就是域名
			//		域名要求服务端进行解析
			if atyp != comm.IPV4 && atyp != comm.Domain && atyp != comm.IPV6 {
				log.Printf("request stage: unexpeceted atyp(%v), quiting handler goroutine: %v\n", atyp, err)
				return
			}

			var dstAddrBytes []byte = nil
			// ipv4 或 ipv6 或 domain
			var dstAddrType string
			switch atyp {
			case comm.IPV4:
				dstAddrType = "ipv4"
				dstAddrBytes = make([]byte, 4)
				_, err := io.ReadFull(tcpConn, dstAddrBytes)
				if err != nil {
					log.Printf("request stage: unexpeceted read error, quiting handler goroutine: %v\n", err)
					return
				}
			case comm.Domain:
				dstAddrType = "domain"
				var nDomainBytes []byte = make([]byte, 1)
				_, err := io.ReadFull(tcpConn, nDomainBytes)
				if err != nil {
					log.Printf("request stage: unexpeceted read error, quiting handler goroutine: %v\n", err)
					return
				}
				if int(nDomainBytes[0]) == 0 {
					log.Printf("request stage: unexpeceted domain bytes length(%v), quiting handler goroutine\n", int(nDomainBytes[0]))
					return
				}
				dstAddrBytes = make([]byte, int(nDomainBytes[0]))
				_, err = io.ReadFull(tcpConn, dstAddrBytes)
				if err != nil {
					log.Printf("request stage: unexpeceted read error, quiting handler goroutine: %v\n", err)
					return
				}
			case comm.IPV6:
				dstAddrType = "ipv6"
				dstAddrBytes = make([]byte, 16)
				_, err := io.ReadFull(tcpConn, dstAddrBytes)
				if err != nil {
					log.Printf("request stage: unexpeceted read error, quiting handler goroutine: %v\n", err)
					return
				}
			}

			// 与服务端正式建立连接
			extraHeader := http.Header{}
			extraHeader.Set("Wsproxy-Token", Token)
			extraHeader.Set("Wsproxy-Protocol", requestProtocolType)
			extraHeader.Set("Wsproxy-Addr-Type", dstAddrType)
			extraHeader.Set("Wsproxy-Addr", string(dstAddrBytes))
			conn, resp, err := websocket.DefaultDialer.Dial(fmt.Sprintf("wss://%v:%v", ServerIP, ServerPort), extraHeader)
			if err != nil {
				log.Printf("request stage: network error, failed to connect to server, quiting handler goroutine: %v\n", err)
				_, err := tcpConn.Write([]byte{0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00})
				if err != nil {
					log.Printf("request stage: write tcp connection error, quiting handler goroutine: %v\n", err)
				}
				return
			}

			status, ok := resp.Header["Status"]
			if !ok {
				log.Printf("request stage: protocol error, failed to create wss connect to server: no Status header, quiting handler goroutine\n")
				_, err := tcpConn.Write([]byte{0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00})
				if err != nil {
					log.Printf("request stage: write tcp connection error, quiting handler goroutine: %v\n", err)
				}
				return
			}
			if len(status) != 1 {
				log.Printf("request stage: protocol error, failed to create wss connect to server: unexpected Status header, quiting handler goroutine\n")
				_, err := tcpConn.Write([]byte{0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00})
				if err != nil {
					log.Printf("request stage: write tcp connection error, quiting handler goroutine: %v\n", err)
				}
				return
			}

			switch status[0] {
			case comm.StatusAuthFailed:
				log.Printf("request stage: auth error, please check your token, quiting handler goroutine\n")
				_, err := tcpConn.Write([]byte{0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00})
				if err != nil {
					log.Printf("request stage: write tcp connection error, quiting handler goroutine: %v\n", err)
				}
				return
			case comm.StatusConnected:
				// 连接成功了, 现在可以开始愉快地通讯了
				break
			case comm.StatusUnexpected:
				log.Printf("request stage: protocol error, unexpected error, quiting handler goroutine\n")
				_, err := tcpConn.Write([]byte{0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00})
				if err != nil {
					log.Printf("request stage: write tcp connection error, quiting handler goroutine: %v\n", err)
				}
				return
			default:
				log.Printf("request stage: protocol error, failed to create wss connect to server: unexpected Status header, quiting handler goroutine\n")
				_, err := tcpConn.Write([]byte{0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00})
				if err != nil {
					log.Printf("request stage: write tcp connection error, quiting handler goroutine: %v\n", err)
				}
				return
			}

			// 可以开始进行收发数据了
		}()
	}
}
