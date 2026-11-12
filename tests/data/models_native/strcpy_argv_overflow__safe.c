// expect-none: DF017
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char user[32];
    if (argc < 2) return 2;
    strncpy(user, argv[1], sizeof(user) - 1);
    user[sizeof(user) - 1] = '\0';
    printf("hello %s\n", user);
    return 0;
}
