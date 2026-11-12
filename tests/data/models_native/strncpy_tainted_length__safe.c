// expect-none: DF017
#include <string.h>
#include "mongoose.h"

static void on_request(struct mg_connection *c, struct mg_http_message *hm) {
    char name[64];
    strncpy(name, "anonymous", sizeof(name) - 1);
    name[sizeof(name) - 1] = 0;
    mg_http_reply(c, 204, "", "");
}
