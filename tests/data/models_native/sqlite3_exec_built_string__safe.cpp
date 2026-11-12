// expect-none: DF004
#include <sqlite3.h>
#include <cstdlib>

int main() {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    sqlite3_open("/var/lib/app/app.db", &db);
    const char *user = std::getenv("QUERY_STRING");
    sqlite3_prepare_v2(db, "SELECT email FROM users WHERE name = ?1", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, user, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    return 0;
}
