// expect: DF012
#include <httplib.h>
#include <sol/sol.hpp>

void evaluate(const httplib::Request &req, httplib::Response &res) {
    sol::state lua;
    lua.open_libraries(sol::lib::base);
    lua.script(req.get_param_value("expr"));
    res.status = 200;
}
