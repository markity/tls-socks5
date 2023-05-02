package main

import "time"

// 本地socks服务器的端口, 地址就是127.0.0.1
var LocalSocks5ServerPort = 1080

// 服务端的ip和端口
var ServerIP = "127.0.0.1"
var ServerPort = 5000

// 握手的超时时间
var WssHandshakeTimeout = time.Second * 5

// 密码
var Token = "random_string_as_token"
