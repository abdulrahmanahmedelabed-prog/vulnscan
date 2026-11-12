// expect-none: DF004
#include <drogon/drogon.h>

void search(const drogon::HttpRequestPtr &req) {
    auto term = req->getParameter("q");
    auto client = drogon::app().getDbClient();
    auto rows = client->execSqlSync("SELECT id FROM posts WHERE title LIKE $1", "%" + term + "%");
    LOG_DEBUG << rows.size();
}
