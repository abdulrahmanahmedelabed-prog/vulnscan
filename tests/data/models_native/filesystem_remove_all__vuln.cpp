// expect: DF011
#include <filesystem>
#include <httplib.h>

void purge(const httplib::Request &req, httplib::Response &res) {
    auto bucket = req.get_param_value("bucket");
    std::filesystem::remove_all("/var/cache/app/" + bucket);
    res.status = 204;
}
