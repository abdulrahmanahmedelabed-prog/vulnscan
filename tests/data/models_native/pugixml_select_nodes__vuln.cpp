// expect: DF015
#include <httplib.h>
#include <pugixml.hpp>

void find(const httplib::Request &req, httplib::Response &res) {
    pugi::xml_document doc;
    doc.load_file("/srv/data/users.xml");
    std::string expr = "//user[@name='" + req.get_param_value("name") + "']";
    auto hits = doc.select_nodes(expr.c_str());
    res.status = hits.empty() ? 404 : 200;
}
