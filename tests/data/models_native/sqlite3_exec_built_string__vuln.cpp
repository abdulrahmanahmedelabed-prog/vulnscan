// expect: DF004
#include <cstdlib>
#include <sqlite3.h>
#include <string>

int main() {
    sqlite3 *db;
    sqlite3_open("/var/lib/app/app.db", &db);
    const char *user = std::getenv("QUERY_STRING");
    std::string sql = "SELECT email FROM users WHERE name = '" + std::string(user) + "'";
    sqlite3_exec(db, sql.c_str(), NULL, NULL, NULL);
    return 0;
}
