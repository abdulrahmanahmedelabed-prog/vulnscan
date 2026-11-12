// expect-none: DF010
#include <cpprest/http_client.h>
#include <httplib.h>

void relay(const httplib::Request &req, httplib::Response &res) {
    auto upstream = req.get_param_value("upstream");
    web::http::client::http_client backend("https://backend.example.com");
    auto reply = backend.request(web::http::methods::GET).get();
    res.status = upstream.empty() ? 400 : reply.status_code();
}
