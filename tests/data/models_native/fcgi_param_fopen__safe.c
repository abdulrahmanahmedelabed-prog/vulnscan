// expect-none: DF005
#include <fcgiapp.h>
#include <stdio.h>
#include <stdlib.h>

void serve(FCGX_Request *request) {
    const char *name = FCGX_GetParam("HTTP_X_REPORT", request->envp);
    int id = atoi(name);
    FILE *fp = fopen("/srv/reports/latest.txt", "r");
    if (fp && id > 0) fclose(fp);
}
