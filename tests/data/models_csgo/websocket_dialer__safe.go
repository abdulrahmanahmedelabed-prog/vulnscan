// expect-none: DF010
package main

import (
	"net/http"

	"github.com/gorilla/websocket"
)

func relay(w http.ResponseWriter, r *http.Request) {
	conn, _, _ := websocket.DefaultDialer.Dial("wss://feed.example.com/stream", nil)
	conn.Close()
}
