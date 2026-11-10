// expect: DF010
package main

import (
	"net/http"
)

func fetch(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	req, _ := http.NewRequest("GET", target, nil)
	http.DefaultClient.Do(req)
}
