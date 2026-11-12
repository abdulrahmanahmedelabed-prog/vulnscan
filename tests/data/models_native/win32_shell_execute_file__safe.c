// expect-none: DF002
#include <windows.h>
#include <shellapi.h>

int main(int argc, char **argv) {
    ShellExecuteA(NULL, "open", "C:\\Program Files\\App\\help.chm", NULL, NULL, SW_SHOWNORMAL);
    return 0;
}
