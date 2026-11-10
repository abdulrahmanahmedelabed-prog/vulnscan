// expect: DF005
package main

import (
	"net/http"
)

func download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	http.ServeFile(w, r, "/srv/files/"+name)
}
