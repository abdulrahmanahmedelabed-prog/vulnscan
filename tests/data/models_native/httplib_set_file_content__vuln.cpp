// expect: DF005
#include <httplib.h>

void serve(const httplib::Request &req, httplib::Response &res) {
    auto name = req.get_param_value("name");
    res.set_file_content("/srv/reports/" + name);
}
