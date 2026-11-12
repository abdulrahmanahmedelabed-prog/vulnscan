// expect-none: DF015
#include <httplib.h>
#include <pugixml.hpp>

void find(const httplib::Request &req, httplib::Response &res) {
    pugi::xml_document doc;
    doc.load_file("/srv/data/users.xml");
    pugi::xpath_variable_set vars;
    vars.set("name", req.get_param_value("name").c_str());
    auto hits = doc.select_nodes("//user[@name=$name]", &vars);
    res.status = hits.empty() ? 404 : 200;
}
