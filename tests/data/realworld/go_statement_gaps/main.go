package main

import (
	"database/sql"
	"net/http"
	"os/exec"
)

var db *sql.DB

type Row struct{ Name string }

func lookup(id string) (*Row, error) {
	rows, err := db.Query("SELECT name FROM users WHERE id = '" + id + "'") // reported (control)
	if err != nil {
		return nil, err // skipped: multi-value return
	}
	defer rows.Close()
	return &Row{Name: "x"}, nil // skipped: multi-value return + keyed composite literal
}

func handler(w http.ResponseWriter, r *http.Request) {
	data := make(map[string]interface{})            // skipped: make(map[...]...)
	args := []string{"-c", r.FormValue("cmd")}      // skipped: slice literal
	exec.Command("sh", args...).Run()               // skipped: variadic spread  -> command injection missed
	w.Write([]byte(r.FormValue("q")))               // skipped: []byte(x) conversion -> reflected XSS missed
	c := &http.Cookie{Name: "u", Value: r.FormValue("u")} // skipped: keyed composite literal
	http.SetCookie(w, c)
	for _, k := range []string{"a", "b"} {          // skipped: range over a literal
		data[k] = r.FormValue(k)
	}
	lookup(r.FormValue("id"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8080", nil)
}
