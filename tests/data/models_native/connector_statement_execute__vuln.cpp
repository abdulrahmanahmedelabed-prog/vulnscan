// expect: DF004
#include <cppconn/statement.h>
#include <mysql_connection.h>
#include <string>

void drop_partition(sql::Connection *con, int argc, char *argv[]) {
    std::string partition = argv[1];
    sql::Statement *stmt = con->createStatement();
    stmt->execute("ALTER TABLE events DROP PARTITION " + partition);
    delete stmt;
}
