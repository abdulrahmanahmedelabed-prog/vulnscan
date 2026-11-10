// expect: DF004
package main

import (
	"net/http"

	"github.com/jmoiron/sqlx"
)

var db *sqlx.DB

func save(w http.ResponseWriter, r *http.Request) {
	table := r.FormValue("table")
	db.NamedExecContext(r.Context(), "INSERT INTO "+table+" (name) VALUES (:name)", nil)
}
