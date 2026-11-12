// expect: DF010
#include <cpprest/http_client.h>
#include <httplib.h>

void relay(const httplib::Request &req, httplib::Response &res) {
    auto upstream = req.get_param_value("upstream");
    web::http::client::http_client backend(upstream);
    auto reply = backend.request(web::http::methods::GET).get();
    res.status = reply.status_code();
}
