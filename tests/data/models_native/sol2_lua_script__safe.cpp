// expect-none: DF012
#include <httplib.h>
#include <sol/sol.hpp>

void evaluate(const httplib::Request &req, httplib::Response &res) {
    sol::state lua;
    lua.open_libraries(sol::lib::base);
    lua["input"] = req.get_param_value("expr");
    lua.script("result = string.len(input)");
    res.status = 200;
}
