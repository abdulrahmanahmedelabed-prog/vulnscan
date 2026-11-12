// expect-none: DF017 DF018
#include <stdio.h>

int main(int argc, char **argv) {
    char banner[64];
    snprintf(banner, sizeof(banner), "Welcome back, %s!", argv[1]);
    puts(banner);
    return 0;
}
