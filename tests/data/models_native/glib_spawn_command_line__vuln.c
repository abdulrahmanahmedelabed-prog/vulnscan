// expect: DF002
#include <glib.h>
#include <fcgiapp.h>

void handle(FCGX_Request *request) {
    const char *name = FCGX_GetParam("HTTP_X_ARCHIVE", request->envp);
    char *line = g_strconcat("tar czf /tmp/out.tgz ", name, NULL);
    g_spawn_command_line_sync(line, NULL, NULL, NULL, NULL);
    g_free(line);
}
