// expect: DF017
#include <stdio.h>

int main(int argc, char **argv) {
    char banner[64];
    sprintf(banner, "Welcome back, %s!", argv[1]);
    puts(banner);
    return 0;
}
