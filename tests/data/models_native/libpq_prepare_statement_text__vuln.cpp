// expect: DF004
#include <fcgiapp.h>
#include <libpq-fe.h>
#include <string>

void handle(FCGX_Request *request, PGconn *pg) {
    const char *column = FCGX_GetParam("HTTP_X_SORT", request->envp);
    std::string text = std::string("SELECT id FROM orders ORDER BY ") + column;
    PQprepare(pg, "orders_sorted", text.c_str(), 0, NULL);
}
