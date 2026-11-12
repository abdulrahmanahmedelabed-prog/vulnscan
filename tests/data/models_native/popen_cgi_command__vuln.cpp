// expect: DF002
#include <cstdio>
#include <cstdlib>
#include <string>

int main() {
    const char *host = std::getenv("QUERY_STRING");
    std::string cmd = std::string("ping -c 1 ") + host;
    FILE *out = popen(cmd.c_str(), "r");
    pclose(out);
    return 0;
}
