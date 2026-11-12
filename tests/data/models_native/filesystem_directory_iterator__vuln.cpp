// expect: DF005
#include <filesystem>
#include <httplib.h>

void listing(const httplib::Request &req, httplib::Response &res) {
    auto folder = req.get_param_value("dir");
    std::string names;
    for (const auto &item : std::filesystem::directory_iterator("/srv/share/" + folder)) {
        names += item.path().filename().string();
    }
    res.status = names.empty() ? 404 : 200;
}
