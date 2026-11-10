// expect: DF010
package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

func proxy(w http.ResponseWriter, r *http.Request) {
	var target url.URL
	target.Scheme = "http"
	target.Host = r.Header.Get("X-Backend")
	httputil.NewSingleHostReverseProxy(&target).ServeHTTP(w, r)
}
