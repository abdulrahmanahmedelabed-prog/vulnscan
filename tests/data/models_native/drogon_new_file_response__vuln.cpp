// expect: DF005
#include <drogon/drogon.h>

drogon::HttpResponsePtr download(const drogon::HttpRequestPtr &req) {
    auto name = req->getParameter("file");
    return drogon::HttpResponse::newFileResponse("/srv/downloads/" + name);
}
