// expect: DF018
#include <boost/format.hpp>
#include <iostream>
#include <string>

int main(int argc, char *argv[]) {
    std::string pattern = argv[1];
    auto line = boost::format(pattern);
    std::cout << line.str() << std::endl;
    return 0;
}
