// expect-none: DF002
#include <windows.h>

int main(int argc, char **argv) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi;
    char line[] = "C:\\Windows\\System32\\ipconfig.exe /all";
    CreateProcessA(NULL, line, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    return 0;
}
