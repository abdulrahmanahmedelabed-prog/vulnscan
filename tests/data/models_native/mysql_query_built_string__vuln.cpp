// expect: DF004
#include <fcgiapp.h>
#include <mysql/mysql.h>
#include <string>

void handle(FCGX_Request *request, MYSQL *db) {
    const char *sku = FCGX_GetParam("QUERY_STRING", request->envp);
    std::string statement = "SELECT price FROM items WHERE sku = '";
    statement += sku;
    statement += "'";
    mysql_query(db, statement.c_str());
}
