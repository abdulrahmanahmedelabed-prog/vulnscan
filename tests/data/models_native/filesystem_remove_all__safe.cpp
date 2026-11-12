// expect-none: DF011
#include <filesystem>
#include <httplib.h>

void purge(const httplib::Request &req, httplib::Response &res) {
    auto bucket = req.get_param_value("bucket");
    std::filesystem::remove_all("/var/cache/app/thumbnails");
    res.status = bucket.empty() ? 400 : 204;
}
