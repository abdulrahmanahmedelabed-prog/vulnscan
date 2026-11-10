// expect: DF004
package main

import (
	"net/http"

	"github.com/jmoiron/sqlx"
)

var db *sqlx.DB

type Item struct{ Name string }

func list(w http.ResponseWriter, r *http.Request) {
	sort := r.FormValue("sort")
	var items []Item
	sqlx.Select(db, &items, "SELECT name FROM items ORDER BY "+sort)
}
