// expect: DF017
#include <string.h>
#include "mongoose.h"

static void on_request(struct mg_connection *c, struct mg_http_message *hm) {
    char name[64];
    strncpy(name, hm->query.ptr, hm->query.len);
    mg_http_reply(c, 204, "", "");
}
