package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"

	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte("k"))
var tmpl = template.Must(template.ParseFiles("page.html"))

type Item struct{ Name string }

// SAFE: session lookup, URL parsing, typed JSON decoding, html/template execution, returning an error
func safeHandler(w http.ResponseWriter, r *http.Request) {
	s, err := store.Get(r, "app")
	if err != nil {
		log.Println(err.Error())
		return
	}
	u, _ := url.Parse(r.URL.Query().Get("next"))
	var it Item
	if err := json.NewDecoder(r.Body).Decode(&it); err != nil {
		return
	}
	tmpl.ExecuteTemplate(w, "page", map[string]any{"item": it, "host": u.Host, "s": s.Values["id"]})
}

func bind(r *http.Request, obj any) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	return nil
}

// VULNERABLE twins: SSRF and template built from input
func vulnHandler(w http.ResponseWriter, r *http.Request) {
	http.Get(r.URL.Query().Get("u"))
	t, _ := template.New("x").Parse(r.FormValue("tpl"))
	t.Execute(w, nil)
}

func main() {
	http.HandleFunc("/s", safeHandler)
	http.HandleFunc("/v", vulnHandler)
	http.ListenAndServe(":8080", nil)
}
