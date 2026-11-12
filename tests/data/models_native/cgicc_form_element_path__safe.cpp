// expect-none: DF005
#include <cgicc/Cgicc.h>
#include <fstream>
#include <iostream>

int main() {
    cgicc::Cgicc cgi;
    int page = std::stoi(cgi.getElement("page")->getValue());
    std::ifstream in("/var/www/pages/" + std::to_string(page) + ".txt");
    std::cout << "Content-Type: text/plain\r\n\r\n" << in.rdbuf();
    return 0;
}
