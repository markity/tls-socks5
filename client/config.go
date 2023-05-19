package main

import "time"

// 本地socks服务器的端口, 地址就是127.0.0.1
var LocalSocks5ServerPort = 1080

// 服务端的ip和端口
var ServerIP = "127.0.0.1"
var ServerPort = 5000

// 客户端发送心跳包的时间间隔
var HeartbeatInterval = time.Second * 1
