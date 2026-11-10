// expect-none: DF004
package main

import (
	"net/http"
	"strconv"

	"github.com/jmoiron/sqlx"
)

var db *sqlx.DB

type Item struct{ Name string }

func list(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.FormValue("limit"))
	var items []Item
	sqlx.Select(db, &items, "SELECT name FROM items ORDER BY name LIMIT "+strconv.Itoa(limit))
}
