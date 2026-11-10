// expect-none: DF010
package main

import (
	"net"
	"net/http"
	"time"
)

func probe(w http.ResponseWriter, r *http.Request) {
	addr := "db.internal:5432"
	if r.URL.Query().Get("replica") == "1" {
		addr = "replica.internal:5432"
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, _ := dialer.DialContext(r.Context(), "tcp", addr)
	conn.Close()
}
