// expect-none: DF005
package main

import (
	"net/http"
	"path/filepath"
)

func download(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Query().Get("file"))
	http.ServeFile(w, r, filepath.Join("/srv/files", name))
}
