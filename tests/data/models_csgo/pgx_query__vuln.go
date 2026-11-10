// expect: DF004
package main

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

var pool *pgxpool.Pool

func lookup(w http.ResponseWriter, r *http.Request) {
	sku := r.URL.Query().Get("sku")
	rows, _ := pool.Query(r.Context(), "SELECT price FROM products WHERE sku = '"+sku+"'")
	defer rows.Close()
}
