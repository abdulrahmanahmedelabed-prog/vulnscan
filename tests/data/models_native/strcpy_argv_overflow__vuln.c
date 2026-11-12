// expect: DF017
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char user[32];
    if (argc < 2) return 2;
    strcpy(user, argv[1]);
    printf("hello %s\n", user);
    return 0;
}
