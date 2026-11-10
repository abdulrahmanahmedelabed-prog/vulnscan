// expect-none: DF013
package main

import (
	"log/slog"
	"net/http"
)

func download(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	// slog.String builds a log attribute; nothing is written to the response
	slog.Info("download", slog.String("name", name))
	w.WriteHeader(http.StatusNoContent)
}
