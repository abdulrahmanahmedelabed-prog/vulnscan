// expect-none: DF005
#include <httplib.h>

void serve(const httplib::Request &req, httplib::Response &res) {
    auto year = std::stoi(req.get_param_value("year"));
    res.set_file_content("/srv/reports/" + std::to_string(year) + ".pdf");
}
