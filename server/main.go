package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

// client 和 server用wss通信

var Upgrader = websocket.Upgrader{
	HandshakeTimeout: WssHandshakeTimeout,
	// buffer的大小让库自行选择
	ReadBufferSize:    0,
	WriteBufferSize:   0,
	CheckOrigin:       nil,
	Subprotocols:      []string{"wsproxy"},
	WriteBufferPool:   nil,
	Error:             nil,
	EnableCompression: false,
}

func main() {
	log.Printf("listening on: " + fmt.Sprint(ListenPort))
	http.HandleFunc("/wsproxy", HandlerFunc)
	log.Fatal(http.ListenAndServeTLS(":"+fmt.Sprint(ListenPort), "ca.pem", "ca.key", nil))
}
