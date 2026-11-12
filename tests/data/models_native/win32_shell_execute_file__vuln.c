// expect: DF002
#include <windows.h>
#include <shellapi.h>

int main(int argc, char **argv) {
    ShellExecuteA(NULL, "open", argv[1], NULL, NULL, SW_SHOWNORMAL);
    return 0;
}
