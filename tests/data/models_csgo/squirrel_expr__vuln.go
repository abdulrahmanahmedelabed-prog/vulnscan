// expect: DF004
package main

import (
	"net/http"

	sq "github.com/Masterminds/squirrel"
)

func filter(w http.ResponseWriter, r *http.Request) {
	cond := r.FormValue("where")
	q := sq.Select("*").From("users").Where(sq.Expr(cond))
	q.ToSql()
}
