// expect: DF010
package main

import (
	"net"
	"net/http"
)

func probe(w http.ResponseWriter, r *http.Request) {
	addr := r.FormValue("addr")
	conn, _ := net.Dial("tcp", addr)
	conn.Close()
}
