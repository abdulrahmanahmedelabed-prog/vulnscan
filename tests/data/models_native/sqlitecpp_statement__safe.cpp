// expect-none: DF004
#include <SQLiteCpp/SQLiteCpp.h>
#include <string>

int main(int argc, char *argv[]) {
    SQLite::Database db("app.db3");
    std::string tag = argv[1];
    SQLite::Statement query(db, "SELECT id FROM notes WHERE tag = ?");
    query.bind(1, tag);
    return query.executeStep() ? 0 : 1;
}
