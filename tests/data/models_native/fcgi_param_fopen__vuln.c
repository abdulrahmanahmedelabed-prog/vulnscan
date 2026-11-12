// expect: DF005
#include <fcgiapp.h>
#include <stdio.h>

void serve(FCGX_Request *request) {
    const char *name = FCGX_GetParam("HTTP_X_REPORT", request->envp);
    FILE *fp = fopen(name, "r");
    if (fp) fclose(fp);
}
