// expect: DF018
#include <stdio.h>

int main(int argc, char **argv) {
    char line[256];
    snprintf(line, sizeof(line), argv[1]);
    puts(line);
    return 0;
}
