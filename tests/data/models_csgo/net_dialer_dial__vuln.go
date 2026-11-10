// expect: DF010
package main

import (
	"net"
	"net/http"
	"time"
)

func probe(w http.ResponseWriter, r *http.Request) {
	addr := r.URL.Query().Get("addr")
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, _ := dialer.DialContext(r.Context(), "tcp", addr)
	conn.Close()
}
