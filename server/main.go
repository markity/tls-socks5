package main

import (
	"fmt"
	"log"
	"net/http"
)

// client 和 server用wss通信
func main() {
	log.Printf("listening on: " + fmt.Sprint(ListenPort))
	http.HandleFunc("/wsproxy", HandlerFunc)
	log.Fatal(http.ListenAndServeTLS(fmt.Sprintf("0.0.0.0:%v", ListenPort), "ca.pem", "ca.key", nil))
}
