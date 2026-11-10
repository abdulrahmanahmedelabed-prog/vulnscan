// expect: DF004
package main

import (
	"net/http"

	"github.com/jmoiron/sqlx"
)

var db *sqlx.DB

func find(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	rows, _ := db.Queryx("SELECT * FROM accounts WHERE email = '" + email + "'")
	defer rows.Close()
}
