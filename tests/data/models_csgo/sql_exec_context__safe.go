// expect-none: DF004
package main

import (
	"context"
	"database/sql"
)

// A context parameter is not user input: the query is constant.
func purge(ctx context.Context, db *sql.DB) {
	db.ExecContext(ctx, "DELETE FROM sessions WHERE expires < now()")
}
