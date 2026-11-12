// expect-none: DF002
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    const char *domain = getenv("QUERY_STRING");
    printf("Content-Type: text/plain\r\n\r\n");
    printf("%zu\n", strlen(domain));
    return system("/usr/bin/uptime");
}
