package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"example.com/shop/handlers"
)

func RequireLogin(next http.Handler) http.Handler {
	return next
}

func main() {
	r := chi.NewRouter()
	r.Get("/status", handlers.Status)
	r.Route("/articles", func(r chi.Router) {
		r.Get("/", handlers.ListArticles)
		r.Route("/{articleID}", func(r chi.Router) {
			r.Use(RequireLogin)
			r.Put("/", handlers.UpdateArticle)
		})
		r.With(RequireLogin).Post("/", handlers.CreateArticle)
	})
	http.ListenAndServe(":3000", r)
}
