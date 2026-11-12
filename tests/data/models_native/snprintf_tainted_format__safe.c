// expect-none: DF018
#include <stdio.h>

int main(int argc, char **argv) {
    char line[256];
    snprintf(line, sizeof(line), "%s", argv[1]);
    puts(line);
    return 0;
}
