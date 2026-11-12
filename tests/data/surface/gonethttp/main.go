package main

import (
	"database/sql"
	"flag"
	"net/http"
	"os/exec"
)

var db *sql.DB

func search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	rows, _ := db.Query("SELECT id FROM products WHERE name = '" + q + "'")
	defer rows.Close()
}

func convert(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	exec.Command("sh", "-c", "convert "+name).Run()
}

func profile(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(r.PathValue("id")))
}

func basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); !ok {
			w.WriteHeader(401)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("/search", search)
	mux.Handle("/convert", basicAuth(http.HandlerFunc(convert)))
	mux.HandleFunc("GET /users/{id}", profile)
	http.ListenAndServe(*addr, mux)
}
