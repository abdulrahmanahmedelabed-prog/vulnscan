// expect: DF008
#include <microhttpd.h>

static int answer(void *cls, struct MHD_Connection *connection) {
    const char *next = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "next");
    struct MHD_Response *response = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(response, "Location", next);
    return MHD_queue_response(connection, MHD_HTTP_FOUND, response);
}
