// expect-none: DF005
#include <fcgiapp.h>
#include <fcntl.h>
#include <unistd.h>

void handle(FCGX_Request *request, int docroot) {
    const char *doc = FCGX_GetParam("PATH_INFO", request->envp);
    int fd = openat(docroot, "index.html", O_RDONLY);
    close(fd);
}
