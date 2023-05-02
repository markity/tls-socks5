package main

import "time"

// wss握手超时时间
var WssHandshakeTimeout = time.Second * 5

// 服务端监听地址
var ListenPort = 5000

// 密钥
var Token = "random_string_as_token"
