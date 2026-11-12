package handlers

import (
	"html/template"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func Status(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}

func ListArticles(w http.ResponseWriter, r *http.Request) {
	t, _ := template.New("list").Parse(r.URL.Query().Get("layout"))
	t.Execute(w, nil)
}

func UpdateArticle(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "articleID")
	w.Write([]byte(id))
}

func CreateArticle(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(r.Header.Get("X-Author")))
}
