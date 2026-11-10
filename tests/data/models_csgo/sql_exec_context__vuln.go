// expect: DF004
package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func rename(w http.ResponseWriter, r *http.Request) {
	title := r.PostFormValue("title")
	db.ExecContext(r.Context(), "UPDATE notes SET title = '"+title+"' WHERE id = 1")
}
