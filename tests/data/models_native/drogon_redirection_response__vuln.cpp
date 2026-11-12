// expect: DF008
#include <drogon/drogon.h>

drogon::HttpResponsePtr after_login(const drogon::HttpRequestPtr &req) {
    auto next = req->getParameter("next");
    return drogon::HttpResponse::newRedirectionResponse(next);
}
