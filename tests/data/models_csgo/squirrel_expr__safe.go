// expect-none: DF004
package main

import (
	"net/http"

	sq "github.com/Masterminds/squirrel"
)

func filter(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	q := sq.Select("*").From("users").Where("name = ?", name)
	q.ToSql()
}
