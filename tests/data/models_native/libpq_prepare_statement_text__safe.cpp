// expect-none: DF004
#include <fcgiapp.h>
#include <libpq-fe.h>

void handle(FCGX_Request *request, PGconn *pg) {
    const char *owner = FCGX_GetParam("HTTP_X_OWNER", request->envp);
    const char *values[1] = { owner };
    PQprepare(pg, "orders_by_owner", "SELECT id FROM orders WHERE owner = $1", 1, NULL);
    PQexecPrepared(pg, "orders_by_owner", 1, values, NULL, NULL, 0);
}
