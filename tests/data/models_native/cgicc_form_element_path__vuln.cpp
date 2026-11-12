// expect: DF005
#include <cgicc/Cgicc.h>
#include <fstream>
#include <iostream>

int main() {
    cgicc::Cgicc cgi;
    std::string page = cgi.getElement("page")->getValue();
    std::ifstream in("/var/www/pages/" + page);
    std::cout << "Content-Type: text/plain\r\n\r\n" << in.rdbuf();
    return 0;
}
