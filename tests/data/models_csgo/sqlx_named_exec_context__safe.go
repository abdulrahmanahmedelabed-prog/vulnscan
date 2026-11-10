// expect-none: DF004
package main

import (
	"net/http"

	"github.com/jmoiron/sqlx"
)

var db *sqlx.DB

type Row struct{ Name string }

func save(w http.ResponseWriter, r *http.Request) {
	var row Row
	row.Name = r.FormValue("name")
	db.NamedExecContext(r.Context(), "INSERT INTO people (name) VALUES (:name)", row)
}
