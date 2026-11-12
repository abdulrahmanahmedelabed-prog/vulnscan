// expect-none: DF002
#include <glib.h>
#include <fcgiapp.h>

void handle(FCGX_Request *request) {
    const char *name = FCGX_GetParam("HTTP_X_ARCHIVE", request->envp);
    g_spawn_command_line_sync("tar czf /tmp/out.tgz /srv/data", NULL, NULL, NULL, NULL);
    FCGX_FPrintF(request->out, "Status: 202\r\n\r\n");
}
