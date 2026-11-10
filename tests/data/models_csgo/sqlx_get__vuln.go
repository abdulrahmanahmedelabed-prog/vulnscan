// expect: DF004
package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jmoiron/sqlx"
)

var db *sqlx.DB

type User struct{ Name string }

func getUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var u User
	db.Get(&u, "SELECT name FROM users WHERE id = "+id)
}
