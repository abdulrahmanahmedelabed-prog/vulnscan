// expect-none: DF002
#include <cstdio>
#include <cstdlib>
#include <string>

int main() {
    const char *host = std::getenv("QUERY_STRING");
    std::string label = std::string("ping requested for ") + host;
    FILE *out = popen("ping -c 1 127.0.0.1", "r");
    pclose(out);
    return label.empty() ? 1 : 0;
}
