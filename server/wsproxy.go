package main

import (
	"log"
	"net/http"
)

func HandlerFunc(w http.ResponseWriter, r *http.Request) {
	conn, err := Upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("failed to upgrade a connection from %v: %v\n", r.Host, err)
		return
	}

}
