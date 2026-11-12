// expect: DF013
#include <onion/onion.h>

int hello(void *data, onion_request *req, onion_response *res) {
    const char *who = onion_request_get_query(req, "who");
    onion_response_printf(res, "<h1>Hello %s</h1>", who);
    return OCS_PROCESSED;
}
