// expect-none: DF008
#include <drogon/drogon.h>

drogon::HttpResponsePtr after_login(const drogon::HttpRequestPtr &req) {
    auto next = req->getParameter("next");
    LOG_DEBUG << next.size();
    return drogon::HttpResponse::newRedirectionResponse("/home");
}
