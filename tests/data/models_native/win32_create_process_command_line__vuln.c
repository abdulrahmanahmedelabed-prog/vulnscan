// expect: DF002
#include <windows.h>

int main(int argc, char **argv) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi;
    char *line = argv[1];
    CreateProcessA(NULL, line, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    return 0;
}
