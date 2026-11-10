// expect-none: DF004
package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func search(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.URL.Query().Get("name")
	rows, _ := db.QueryContext(ctx, "SELECT id FROM users WHERE name = ?", name)
	defer rows.Close()
}
