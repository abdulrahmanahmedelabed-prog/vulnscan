// expect-none: DF005
#include <fstream>
#include <httplib.h>

void upload(const httplib::Request &req, httplib::Response &res) {
    auto file = req.get_file_value("document");
    std::ofstream out("/var/uploads/incoming.bin", std::ios::binary);
    out << file.content;
    res.status = 201;
}
