// expect-none: DF018
#include <boost/format.hpp>
#include <iostream>
#include <string>

int main(int argc, char *argv[]) {
    std::string user = argv[1];
    auto line = boost::format("hello %1%");
    std::cout << (line % user).str() << std::endl;
    return 0;
}
