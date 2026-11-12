// expect-none: DF002
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    execl("/bin/sh", "sh", "-c", "df -h", (char *)NULL);
    return 1;
}
