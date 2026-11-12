// expect-none: DF005
#include <drogon/drogon.h>

drogon::HttpResponsePtr download(const drogon::HttpRequestPtr &req) {
    auto name = req->getParameter("file");
    LOG_DEBUG << name.size();
    return drogon::HttpResponse::newFileResponse("/srv/downloads/catalog.pdf");
}
