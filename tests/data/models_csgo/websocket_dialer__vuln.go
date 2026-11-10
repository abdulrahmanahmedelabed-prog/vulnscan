// expect: DF010
package main

import (
	"net/http"

	"github.com/gorilla/websocket"
)

func relay(w http.ResponseWriter, r *http.Request) {
	upstream := r.URL.Query().Get("upstream")
	conn, _, _ := websocket.DefaultDialer.Dial(upstream, nil)
	conn.Close()
}
