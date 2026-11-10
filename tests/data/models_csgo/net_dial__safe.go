// expect-none: DF010
package main

import (
	"net"
	"net/http"
)

func probe(w http.ResponseWriter, r *http.Request) {
	conn, _ := net.Dial("tcp", "cache.internal:6379")
	conn.Close()
}
