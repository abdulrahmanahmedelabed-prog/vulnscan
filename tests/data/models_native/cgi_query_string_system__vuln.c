// expect: DF002
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    const char *domain = getenv("QUERY_STRING");
    char *line = g_strdup_printf("/usr/bin/whois %s", domain);
    printf("Content-Type: text/plain\r\n\r\n");
    return system(line);
}
