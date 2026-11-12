// expect-none: DF004
#include <cppconn/prepared_statement.h>
#include <mysql_connection.h>
#include <string>

void drop_partition(sql::Connection *con, int argc, char *argv[]) {
    std::string owner = argv[1];
    sql::PreparedStatement *stmt = con->prepareStatement("DELETE FROM events WHERE owner = ?");
    stmt->setString(1, owner);
    stmt->execute();
    delete stmt;
}
