// expect-none: DF004
#include <fcgiapp.h>
#include <mysql/mysql.h>
#include <string.h>

void handle(FCGX_Request *request, MYSQL *db) {
    const char *sku = FCGX_GetParam("QUERY_STRING", request->envp);
    MYSQL_STMT *stmt = mysql_stmt_init(db);
    MYSQL_BIND bind[1];
    mysql_stmt_prepare(stmt, "SELECT price FROM items WHERE sku = ?", 37);
    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type = MYSQL_TYPE_STRING;
    bind[0].buffer = (char *)sku;
    mysql_stmt_bind_param(stmt, bind);
    mysql_stmt_execute(stmt);
}
