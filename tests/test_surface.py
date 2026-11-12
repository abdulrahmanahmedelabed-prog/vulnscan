"""Attack-surface map (vulnscan/surface.py): entry-point discovery per framework, parameters, auth guards, reachable
sinks, finding links, ranking, every output format and the command line. Sample apps live in tests/data/surface/."""

import csv
import functools
import io
import json
import pathlib
import re
import socket

import pytest

from vulnscan import surface as S

DATA = pathlib.Path(__file__).parent / "data" / "surface"


@functools.lru_cache(maxsize=None)
def surf(name, engine=True):
    return S.build_surface(DATA / name, engine=engine)


def ep(name, method, path, kind="http"):
    hits = [e for e in surf(name).entries if e.kind == kind and e.path == path and (not method or method in e.methods)]
    assert hits, f"{method} {path} not found in {name}: {[(e.method, e.path) for e in surf(name).entries]}"
    return hits[0]


def params(e):
    return {(p.name, p.location) for p in e.params}


def guards(e):
    return " | ".join(g["name"] for g in e.auth["guards"])


def routes(name):
    return {(e.method, e.path) for e in surf(name).entries if e.kind == "http"}


# ------------------------------------------------------------------------------------------------------------ Python
def test_flask_routes_blueprint_prefix_params_and_auth():
    assert routes("flask") == {("GET", "/users"), ("GET", "/greet/<name>"), ("POST", "/ping"), ("GET", "/go"),
                               ("GET,POST", "/profile"), ("GET", "/admin/logs/<path:name>"), ("POST", "/admin/import")}
    users = ep("flask", "GET", "/users")
    assert users.framework == "flask" and users.handler == "users" and users.file == "app.py" and users.line > 1
    assert params(users) == {("name", "query")} and users.auth["status"] == "none"
    assert params(ep("flask", "GET", "/greet/<name>")) == {("name", "path"), ("X-Suffix", "header")}
    ping = ep("flask", "POST", "/ping")
    assert ping.auth["status"] == "protected" and "login_required" in guards(ping) and ("host", "form") in params(ping)
    profile = ep("flask", "POST", "/profile")
    assert profile.auth["status"] == "protected" and profile.auth["guards"][0]["kind"] == "inline"
    assert {("display_name", "body"), ("theme", "cookie")} <= params(profile)
    logs = ep("flask", "GET", "/admin/logs/<path:name>")
    assert logs.auth["status"] == "protected" and "before_request: require_admin" in guards(logs)
    assert ("dump", "file") in params(ep("flask", "POST", "/admin/import"))
    assert ep("flask", "", "purge", kind="cli").framework == "click"


def test_flask_sinks_through_call_graph_and_proven_findings():
    users = ep("flask", "GET", "/users")
    sql = [s for s in users.sinks if s.category == "sql"]
    assert sql and sql[0].function == "find_user" and sql[0].depth == 1 and sql[0].proven and sql[0].origin == "model"
    assert "find_user" in users.reachable and users.findings and users.findings[0]["direct"]
    assert re.fullmatch(r"[0-9a-f]{16}:\d+", users.findings[0]["fingerprint"])
    assert "table:users" in users.stores
    assert ep("flask", "GET", "/greet/<name>").sink_categories[0] == "template"
    assert "command" in ep("flask", "POST", "/ping").sink_categories
    assert "redirect" in ep("flask", "GET", "/go").sink_categories
    assert "file" in ep("flask", "GET", "/admin/logs/<path:name>").sink_categories
    assert not ep("flask", "POST", "/admin/import").reaches_sink


def test_django_urls_include_views_and_drf():
    r = routes("django")
    assert {("ANY", "/"), ("ANY", "/shop/search/"), ("GET,POST", "/shop/export/(?P<fmt>\\w+)/"), ("ANY", "/reports/<int:year>/"),
            ("GET,POST", "/shop/api/stock/"), ("GET", "/shop/api/products/"), ("POST", "/shop/api/products/"),
            ("GET", "/shop/api/products/{pk}/"), ("DELETE", "/shop/api/products/{pk}/"),
            ("POST", "/shop/api/products/{pk}/restock/")} <= r
    search = ep("django", "ANY", "/shop/search/")
    assert search.framework == "django" and search.file == "shop/views.py" and params(search) == {("q", "query")}
    assert search.sink_categories == ["sql"] and search.risk_level == "critical" and "table:shop_product" in search.stores
    export = ep("django", "GET", "/shop/export/(?P<fmt>\\w+)/")
    assert export.handler == "ExportView" and "LoginRequiredMixin" in guards(export) and ("fmt", "path") in params(export)
    assert {"command", "deserialization"} <= set(export.sink_categories)
    assert "login_required" in guards(ep("django", "ANY", "/reports/<int:year>/"))          # wrapper in urls.py
    lst = ep("django", "GET", "/shop/api/products/")
    assert lst.framework == "drf" and lst.auth["status"] == "protected" and "DEFAULT_PERMISSION_CLASSES" in guards(lst)
    restock = ep("django", "POST", "/shop/api/products/{pk}/restock/")
    assert restock.auth["status"] == "public" and "AllowAny" in guards(restock) and ("amount", "body") in params(restock)
    assert ep("django", "POST", "/shop/api/stock/").auth["status"] == "public"
    # `request.GET.get(...)` must not be resolved to ExportView.get (the only project method called `get`)
    assert not ep("django", "POST", "/shop/api/stock/").sinks


def test_fastapi_router_prefix_dependencies_and_typed_params():
    assert routes("fastapi") == {("GET", "/fetch"), ("GET", "/me"), ("WEBSOCKET", "/ws"), ("GET", "/items/{item_id}"),
                                 ("POST", "/items/"), ("POST", "/items/{item_id}/image")}
    fetch = ep("fastapi", "GET", "/fetch")
    assert params(fetch) == {("url", "query"), ("x-trace", "header")} and fetch.auth["status"] == "none"
    assert "ssrf" in fetch.sink_categories and fetch.risk_level == "critical"
    me = ep("fastapi", "GET", "/me")
    assert me.auth["status"] == "protected" and "get_current_user" in guards(me) and params(me) == {("verbose", "query")}
    item = ep("fastapi", "GET", "/items/{item_id}")
    assert params(item) == {("item_id", "path"), ("q", "query"), ("session_id", "cookie")}
    assert item.auth["guards"][0]["kind"] == "dependency"                 # include_router(..., dependencies=[Depends(...)])
    create = ep("fastapi", "POST", "/items/")
    assert [(p.name, p.location, p.type) for p in create.params] == [("item", "body", "Item")]
    assert "file" in create.sink_categories
    assert ("image", "file") in params(ep("fastapi", "POST", "/items/{item_id}/image"))
    assert not ep("fastapi", "WEBSOCKET", "/ws").params


def test_python_cli_commands_and_background_jobs():
    kinds = {(e.kind, e.path, e.framework) for e in surf("pycli").entries}
    assert kinds == {("cli", "extract", "click"), ("job", "resize", "celery"), ("cli", "backup.py", "argparse")}
    extract = ep("pycli", "", "extract", kind="cli")
    assert params(extract) == {("target", "arg"), ("archive", "arg")} and "command" in extract.sink_categories
    assert extract.risk_level == "medium"                                   # proven, but not remotely reachable by itself
    assert params(ep("pycli", "", "backup.py", kind="cli")) == {("dest", "arg")}
    assert params(ep("pycli", "", "resize", kind="job")) == {("path", "message"), ("width", "message")}


# ----------------------------------------------------------------------------------------------- JavaScript/TypeScript
def test_express_mounts_router_chain_and_middleware():
    assert routes("express") == {("GET", "/health"), ("POST", "/login"), ("GET", "/api/users/:id"), ("GET", "/api/users/search"),
                                 ("POST", "/api/users/ping"), ("GET", "/api/admin/logs"), ("GET", "/api/admin/settings"),
                                 ("PUT", "/api/admin/settings")}
    assert params(ep("express", "POST", "/login")) == {("username", "body"), ("password", "body")}
    search = ep("express", "GET", "/api/users/search")
    assert params(search) == {("q", "query"), ("accept-language", "header")} and search.auth["status"] == "none"
    logs = ep("express", "GET", "/api/admin/logs")
    assert logs.auth == {"status": "protected", "guards": [{"name": "requireAuth", "kind": "middleware"}]}
    put = ep("express", "PUT", "/api/admin/settings")
    assert put.handler == "saveSettings" and ("value", "body") in params(put) and put.auth["status"] == "protected"
    ping = ep("express", "POST", "/api/users/ping")
    cmd = [s for s in ping.sinks if s.category == "command"][0]
    assert cmd.function == "runPing" and cmd.proven and ping.risk_level == "critical"
    assert ep("express", "GET", "/api/users/:id").sink_categories == ["sql"]
    assert surf("express").entries[0].risk_level == "critical" and surf("express").entries[-1].auth["status"] == "protected"


def test_koa_and_fastify():
    proxy = ep("koa", "GET", "/api/proxy")
    assert proxy.framework == "koa" and params(proxy) == {("url", "query")} and "ssrf" in proxy.sink_categories
    notes = ep("koa", "POST", "/api/notes")
    assert notes.auth["status"] == "protected" and guards(notes).startswith("jwt(") and ("text", "body") in params(notes)
    assert routes("fastify") == {("GET", "/items/:itemId"), ("DELETE", "/items/:itemId"), ("GET", "/download"),
                                 ("POST", "/profile")}
    assert "fastify.verifyJwt" in guards(ep("fastify", "DELETE", "/items/:itemId"))
    assert ep("fastify", "GET", "/items/:itemId").auth["status"] == "none"
    profile = ep("fastify", "POST", "/profile")                              # fastify.route({method, url, preHandler})
    assert "fastify.authenticate" in guards(profile) and ("name", "body") in params(profile)
    assert "file" in ep("fastify", "GET", "/download").sink_categories


def test_nestjs_controller_guards_and_non_http_entries():
    find_all = ep("nest", "GET", "/api/v1/cats")                           # setGlobalPrefix + @Controller + @Get
    assert find_all.framework == "nestjs" and find_all.handler == "CatsController.findAll"
    assert find_all.auth["status"] == "public" and params(find_all) == {("breed", "query"), ("x-tenant", "header")}
    remove = ep("nest", "DELETE", "/api/v1/cats/:id")
    assert remove.auth["status"] == "protected" and "AuthGuard('jwt')" in guards(remove)
    assert params(remove) == {("id", "path")} and "command" in remove.sink_categories
    assert [(p.name, p.location, p.type) for p in ep("nest", "POST", "/api/v1/cats").params] == [("dto", "body", "CreateCatDto")]
    assert ep("nest", "", "cats.created", kind="consumer").handler == "CatsController.onCreated"
    assert ep("nest", "", "0 3 * * *", kind="job").handler == "CatsController.cleanup"


def test_nextjs_pages_and_app_router():
    assert routes("next") == {("ANY", "/api/hello"), ("DELETE", "/api/users/[id]"), ("GET", "/api/items/[id]"),
                              ("PUT", "/api/items/[id]")}
    user = ep("next", "DELETE", "/api/users/[id]")
    assert user.auth["status"] == "protected" and "getServerSession" in guards(user) and ("id", "path") in params(user)
    assert "sql" in user.sink_categories
    get = ep("next", "GET", "/api/items/[id]")
    assert params(get) == {("id", "path"), ("callback", "query")} and "ssrf" in get.sink_categories
    assert S.openapi_path(get.path) == "/api/items/{id}"


# ------------------------------------------------------------------------------------------------------- Java / Kotlin
def test_spring_mvc_annotations_security_config_listeners_and_schedules():
    assert routes("spring") == {("GET", "/api/orders/{id}"), ("GET", "/api/orders/search"), ("POST", "/api/orders"),
                                ("GET", "/api/orders/export"), ("DELETE", "/actuator/health/{probe}")}
    search = ep("spring", "GET", "/api/orders/search")
    assert search.auth["status"] == "public" and "permitAll" in guards(search)
    assert params(search) == {("q", "query"), ("sort", "query")} and search.risk_level == "critical"
    assert search.sinks[0].category == "sql" and search.sinks[0].proven and "table:orders" in search.stores
    get = ep("spring", "GET", "/api/orders/{id}")
    assert params(get) == {("id", "path"), ("X-Tenant", "header")} and "anyRequest().authenticated" in guards(get)
    create = ep("spring", "POST", "/api/orders")
    assert guards(create).startswith("@PreAuthorize") and [(p.name, p.location) for p in create.params] == [("body", "body")]
    export = ep("spring", "GET", "/api/orders/export")
    assert 'hasRole("ADMIN")' in guards(export) and ("sid", "cookie") in params(export)
    cmd = [s for s in export.sinks if s.category == "command"][0]            # through ReportService.export
    assert cmd.file.endswith("ReportService.java") and cmd.depth == 1 and cmd.function == "ReportService.export"
    paid = ep("spring", "", "orders.paid", kind="consumer")
    assert paid.framework == "kafka" and "command" in paid.sink_categories
    assert ep("spring", "", "0 0 * * * *", kind="job").framework == "spring-scheduling"


def test_jaxrs_servlets_webxml_and_kotlin():
    avatar = ep("jaxrs", "GET", "/users/{id}/avatar")
    assert avatar.framework == "jax-rs" and params(avatar) == {("id", "path"), ("size", "query")}
    assert '@RolesAllowed("user")' in guards(avatar) and "file" in avatar.sink_categories
    register = ep("jaxrs", "POST", "/users")
    assert register.auth["status"] == "public" and params(register) == {("dto", "body"), ("X-Forwarded-For", "header")}
    assert guards(ep("jaxrs", "DELETE", "/users/{id}")).startswith('@RolesAllowed("admin")')
    do_get = ep("servlet", "GET", "/legacy/report")
    assert do_get.framework == "servlet" and do_get.handler == "LegacyServlet.doGet" and do_get.auth["status"] == "none"
    assert params(do_get) == {("name", "query"), ("User-Agent", "header")} and "sql" in do_get.sink_categories
    do_post = ep("servlet", "POST", "/legacy/report")
    assert do_post.auth["status"] == "protected" and "redirect" in do_post.sink_categories
    upload = ep("servlet", "POST", "/admin/upload")                          # mapped and protected in web.xml
    assert upload.handler == "UploadServlet.doPost" and "security-constraint" in guards(upload)
    preview = ep("kotlin", "GET", "/notes/preview")
    assert preview.language == "kotlin" and params(preview) == {("url", "query")} and "ssrf" in preview.sink_categories
    assert ep("kotlin", "GET", "/notes/{id}").handler == "NoteController.one"            # expression-bodied function
    update = ep("kotlin", "PUT", "/notes/{id}")
    assert '@Secured("ROLE_EDITOR")' in guards(update) and ("note", "body") in params(update)


# ------------------------------------------------------------------------------------------------------------------ C#
def test_aspnet_controllers_attribute_and_conventional_routing():
    assert routes("aspnet") == {("GET", "/api/Products/{id}"), ("GET", "/api/Products/search"), ("POST", "/api/Products"),
                                ("POST", "/api/Products/convert"), ("ANY", "/Home/Index"), ("POST", "/Home/Go")}
    search = ep("aspnet", "GET", "/api/Products/search")
    assert search.auth["status"] == "public" and guards(search) == "[AllowAnonymous]"       # overrides the class [Authorize]
    assert params(search) == {("term", "query"), ("order", "query")} and "sql" in search.sink_categories
    assert search.risk_level == "critical"
    get = ep("aspnet", "GET", "/api/Products/{id}")
    assert get.auth["status"] == "protected" and params(get) == {("id", "path"), ("X-Api-Version", "header")}
    assert 'Roles = "Admin"' in guards(ep("aspnet", "POST", "/api/Products"))
    convert = ep("aspnet", "POST", "/api/Products/convert")
    assert ("file", "form") in params(convert) and "command" in convert.sink_categories
    go = ep("aspnet", "POST", "/Home/Go")
    assert go.framework == "aspnet-mvc" and go.auth["status"] == "none" and "redirect" in go.sink_categories


def test_aspnet_minimal_api_groups_and_endpoint_auth():
    assert routes("minimalapi") == {("GET", "/files/{name}"), ("POST", "/todos"), ("DELETE", "/admin/todos/{id}"),
                                    ("GET", "/admin/ping")}
    files = ep("minimalapi", "GET", "/files/{name}")
    assert files.auth["status"] == "none" and params(files) == {("name", "path")} and "file" in files.sink_categories
    todos = ep("minimalapi", "POST", "/todos")
    assert todos.auth["status"] == "protected" and [(p.name, p.location, p.type) for p in todos.params] == [("todo", "body", "Todo")]
    assert 'RequireAuthorization("AdminOnly")' in guards(ep("minimalapi", "DELETE", "/admin/todos/{id}"))     # MapGroup
    ping = ep("minimalapi", "GET", "/admin/ping")
    assert ping.auth["status"] == "public" and ping.handler == "Handlers.Ping" and params(ping) == {("host", "query")}
    assert "command" in ping.sink_categories


# ------------------------------------------------------------------------------------------------------------------ Go
def test_go_net_http_and_cli():
    search = ep("gonethttp", "ANY", "/search")
    assert search.framework == "net/http" and search.handler == "search" and params(search) == {("q", "query")}
    assert search.sink_categories == ["sql"] and search.risk_level == "critical" and "table:products" in search.stores
    convert = ep("gonethttp", "ANY", "/convert")
    assert convert.auth["status"] == "protected" and "basicAuth" in guards(convert) and ("name", "form") in params(convert)
    profile = ep("gonethttp", "GET", "/users/{id}")                          # Go 1.22 "GET /users/{id}"
    assert params(profile) == {("id", "path")}
    cli = ep("gonethttp", "", "main", kind="cli")
    assert cli.framework == "flag" and params(cli) == {("addr", "arg")} and not cli.sinks


def test_gin_echo_chi_groups_and_middleware():
    assert routes("gin") == {("GET", "/download"), ("GET", "/users/:id"), ("POST", "/admin/fetch"), ("DELETE", "/api/v1/items/:id")}
    assert "file" in ep("gin", "GET", "/download").sink_categories
    assert params(ep("gin", "GET", "/users/:id")) == {("id", "path"), ("X-Trace", "header")}
    fetch = ep("gin", "POST", "/admin/fetch")
    assert "AuthRequired()" in guards(fetch) and "ssrf" in fetch.sink_categories and ("url", "form") in params(fetch)
    assert ep("gin", "DELETE", "/api/v1/items/:id").auth["status"] == "protected"            # v1.Use(AuthRequired())
    go = ep("echo", "GET", "/go")
    assert go.framework == "echo" and "redirect" in go.sink_categories and go.auth["status"] == "none"
    note = ep("echo", "POST", "/notes/:id")
    assert note.auth["status"] == "protected" and "echojwt.JWT" in guards(note) and ("text", "form") in params(note)
    assert routes("chi") == {("GET", "/status"), ("GET", "/articles/"), ("PUT", "/articles/{articleID}/"), ("POST", "/articles/")}
    lst = ep("chi", "GET", "/articles/")
    assert lst.handler == "handlers.ListArticles" and lst.auth["status"] == "none" and "template" in lst.sink_categories
    assert lst.sinks[0].file == "handlers/articles.go"
    assert "RequireLogin" in guards(ep("chi", "PUT", "/articles/{articleID}/"))              # r.Use inside r.Route
    assert "RequireLogin" in guards(ep("chi", "POST", "/articles/"))                         # r.With(...).Post


# ----------------------------------------------------------------------------------------------------------------- PHP
def test_laravel_routes_groups_resources_and_controllers():
    r = routes("laravel")
    assert r == {("GET", "/"), ("GET", "/search"), ("GET", "/admin/reports/{name}"), ("POST", "/admin/reports"),
                 ("GET", "/photos"), ("GET", "/photos/{photo}"), ("DELETE", "/photos/{photo}"),
                 ("POST", "/api/v1/reports/export"), ("GET,POST", "/api/webhook")}
    show = ep("laravel", "GET", "/admin/reports/{name}")
    assert show.handler == "ReportController@show" and show.file.endswith("ReportController.php")
    assert guards(show) == "auth | verified" and params(show) == {("name", "path"), ("format", "query")}
    store = ep("laravel", "POST", "/admin/reports")
    assert "can:create,report" in guards(store) and "StoreReportRequest::authorize()" in guards(store)
    assert {("title", "body"), ("body", "body")} <= params(store)                             # FormRequest::rules()
    assert ep("laravel", "DELETE", "/photos/{photo}").auth["status"] == "protected"          # $this->middleware('auth')->except
    assert ep("laravel", "GET", "/photos/{photo}").auth["status"] == "none"
    export = ep("laravel", "POST", "/api/v1/reports/export")
    assert "auth:sanctum" in guards(export) and "command" in export.sink_categories
    assert "deserialization" in ep("laravel", "POST", "/api/webhook").sink_categories
    assert "sql" in ep("laravel", "GET", "/search").sink_categories
    prune = ep("laravel", "", "reports:prune", kind="cli")
    assert prune.framework == "laravel-artisan" and params(prune) == {("days", "arg"), ("force", "arg")}


def test_symfony_attributes_annotations_and_access_control():
    assert routes("symfony") == {("GET", "/articles/{slug}"), ("POST", "/articles/{id}/edit"), ("GET", "/articles/legacy/list"),
                                 ("POST", "/admin/import")}
    show = ep("symfony", "GET", "/articles/{slug}")
    assert show.handler == "ArticleController::show" and params(show) == {("slug", "path"), ("tpl", "query")}
    assert show.auth["status"] == "none" and "template" in show.sink_categories
    edit = ep("symfony", "POST", "/articles/{id}/edit")
    assert "IsGranted('ROLE_EDITOR')" in guards(edit) and ("title", "form") in params(edit)
    imp = ep("symfony", "POST", "/admin/import")
    assert imp.auth["guards"][0]["kind"] == "config" and "ROLE_ADMIN" in guards(imp)        # security.yaml access_control


def test_plain_php_scripts():
    download = ep("phpplain", "GET", "/download.php")
    assert download.framework == "php" and params(download) == {("file", "query"), ("sid", "cookie")}
    assert download.auth["status"] == "none" and "file" in download.sink_categories and download.risk_level == "critical"
    admin = ep("phpplain", "POST", "/admin.php")
    assert admin.auth["status"] == "protected" and "sql" in admin.sink_categories and "table:accounts" in admin.stores
    assert [s.function for s in admin.sinks if s.category == "sql"] == ["run_query"]         # through includes/db.php
    assert ep("phpplain", "", "cron.php", kind="cli").framework == "php-cli"
    assert all(e.file != "includes/db.php" for e in surf("phpplain").entries)                # a library, not an entry point


# ---------------------------------------------------------------------------------------------------------------- Ruby
def test_rails_routes_controllers_filters_jobs_and_rake():
    assert routes("rails") == {("GET", "/"), ("GET", "/search"), ("GET", "/products"), ("POST", "/products"),
                               ("GET", "/products/:id"), ("POST", "/products/:id/publish"), ("DELETE", "/admin/users/:id"),
                               ("GET", "/admin/export"), ("ANY", "/sidekiq")}
    search = ep("rails", "GET", "/search")
    assert search.handler == "products#search" and search.file == "app/controllers/products_controller.rb"
    assert search.auth["status"] == "public" and "skip_before_action" in guards(search)
    assert "sql" in search.sink_categories and search.risk_level == "critical" and "model:Product" in search.stores
    create = ep("rails", "POST", "/products")
    assert create.auth["status"] == "protected" and {("name", "body"), ("price", "body")} <= params(create)   # strong params
    publish = ep("rails", "POST", "/products/:id/publish")
    assert {("id", "path"), ("channel", "any")} <= params(publish) and "command" in publish.sink_categories
    destroy = ep("rails", "DELETE", "/admin/users/:id")
    assert destroy.handler == "admin/users#destroy" and guards(destroy).startswith("before_action :require_admin")
    assert "before_action :authenticate_user!" in guards(destroy)                            # inherited from ApplicationController
    assert ep("rails", "ANY", "/sidekiq").framework == "rails-mount"
    job = ep("rails", "", "ThumbnailJob", kind="job")
    assert job.framework == "activejob" and params(job) == {("path", "message"), ("size", "message")}
    assert ep("rails", "", "cleanup:uploads", kind="cli").framework == "rake"


def test_sinatra():
    fetch = ep("sinatra", "GET", "/fetch")
    assert fetch.framework == "sinatra" and fetch.auth["status"] == "none" and params(fetch) == {("url", "any")}
    assert fetch.reaches_sink
    assert params(ep("sinatra", "GET", "/hello/:name")) == {("name", "path")}
    run = ep("sinatra", "POST", "/admin/run")
    assert run.auth["status"] == "protected" and "command" in run.sink_categories            # before '/admin/*' filter


def test_more_frameworks_from_inline_sources():
    files = {
        "g/main.go": 'package main\nimport ("github.com/gorilla/mux"; "net/http")\n'
                     'func h(w http.ResponseWriter, r *http.Request){ _ = mux.Vars(r)["id"] }\n'
                     'func main(){ r := mux.NewRouter(); api := r.PathPrefix("/api").Subrouter(); '
                     'api.HandleFunc("/u/{id}", h).Methods("GET", "POST"); api.Use(authMiddleware) }\n',
        "f/main.go": 'package main\nimport "github.com/gofiber/fiber/v2"\nfunc main(){ app := fiber.New(); '
                     'app.Get("/f/:id", func(c *fiber.Ctx) error { return c.SendString(c.Params("id")) }) }\n',
        "c/root.go": 'package cmd\nimport "github.com/spf13/cobra"\nvar serveCmd = &cobra.Command{\n\tUse: "serve [port]",\n'
                     '\tRun: runServe,\n}\nfunc runServe(cmd *cobra.Command, args []string) {}\n',
        "az/Fn.cs": 'public class Fn {\n [Function("Hello")]\n public IActionResult Run([HttpTrigger(AuthorizationLevel.Anonymous, '
                    '"get", "post", Route = "hello/{name}")] HttpRequest req, string name) { return null; }\n [Function("Q")]\n'
                    ' public void OnMsg([QueueTrigger("orders")] string msg) { }\n}\n',
        "st/app.py": 'from starlette.applications import Starlette\nfrom starlette.routing import Route\n'
                     'async def home(request):\n    return None\napp = Starlette(routes=[Route("/s", home, methods=["POST"])])\n',
        "ai/app.py": 'from aiohttp import web\nasync def hello(request):\n    return web.Response(text=request.query["n"])\n'
                     'app = web.Application()\napp.router.add_get("/aio", hello)\n',
        "routes/web.php": "<?php\nRoute::group(['prefix' => 'adm', 'middleware' => ['auth']], function () {\n"
                          "  Route::any('/x', 'XController@run');\n  Route::controller(YController::class)->group(function () "
                          "{ Route::get('/y/{id}', 'show'); });\n});\nRoute::view('/about', 'about');\n",
        "lam/handler.py": 'def lambda_handler(event, context):\n    return event["body"]\n',
        "sock/app.py": 'import socketio\nsio = socketio.Server()\n@sio.on("chat")\ndef chat(sid, data):\n    pass\n',
        "ex/app.ts": "import express from 'express';\nconst app = express();\nconst api = express.Router();\n"
                     "api.use(passport.authenticate('jwt'));\napi.get('/t', asyncHandler(async (req: Request, res: Response) => "
                     "{ res.json(req.query.x); }));\napp.use('/v2', api);\n",
    }
    s = S.build_surface_from_files(files)
    assert not s.notes
    got = {(e.kind, e.method, e.path, e.framework, e.auth["status"]) for e in s.entries}
    assert got == {
        ("http", "GET,POST", "/api/u/{id}", "gorilla", "protected"), ("http", "GET", "/f/:id", "fiber", "none"),
        ("cli", "", "serve", "cobra", "none"), ("http", "GET,POST", "/api/hello/{name}", "azure-functions", "public"),
        ("consumer", "", "orders", "azure-functions", "none"), ("http", "POST", "/s", "starlette", "none"),
        ("http", "GET", "/aio", "aiohttp", "none"), ("http", "ANY", "/adm/x", "laravel", "protected"),
        ("http", "GET", "/adm/y/{id}", "laravel", "protected"), ("http", "GET", "/about", "laravel", "none"),
        ("consumer", "", "lambda_handler", "aws-lambda", "none"), ("consumer", "", "chat", "socketio", "none"),
        ("http", "GET", "/v2/t", "express", "protected")}


# ------------------------------------------------------------------------------------------- cross-cutting behaviour
ALL = ("flask", "django", "fastapi", "pycli", "express", "koa", "fastify", "nest", "next", "spring", "jaxrs", "servlet",
       "kotlin", "aspnet", "minimalapi", "gonethttp", "gin", "echo", "chi", "laravel", "symfony", "phpplain", "rails", "sinatra")


@pytest.mark.parametrize("name", ALL)
def test_every_sample_is_ranked_and_renders_in_every_format(name):
    s = surf(name)
    assert s.entries and not s.notes
    order = [S._LEVELS.index(e.risk_level) for e in s.entries]
    assert order == sorted(order)                                            # riskiest first
    assert len({e.id for e in s.entries}) == len(s.entries) and all(re.fullmatch(r"EP[0-9a-f]{10}", e.id) for e in s.entries)
    for e in s.entries:
        assert 0 <= e.risk <= 100 and e.line >= 1 and e.file and e.auth["status"] in ("none", "public", "protected")
        assert all(sk.category in S.SINK_CATEGORIES and sk.line >= 1 for sk in e.sinks)
    for fmt in S.FORMATS:
        for lang in ("en", "ar"):
            assert S.render(s, fmt, lang).strip()
    doc = json.loads(S.render_json(s))
    assert doc["tool"] == "kashif-surface" and doc["static_only"] is True and len(doc["entries"]) == len(s.entries)
    assert json.loads(S.render_json(s, "ar"))["summary"] == doc["summary"]


def test_ranking_puts_unauthenticated_routes_that_reach_a_sink_first():
    s = S.build_surface(DATA)                                                # all the sample apps as one project
    assert len(s.entries) > 100
    top = s.entries[:10]
    assert all(e.kind == "http" and e.unauthenticated and e.reaches_sink and e.findings for e in top)
    assert all(e.risk_level == "critical" for e in top)
    tail = s.entries[-10:]
    assert all(not e.reaches_sink for e in tail)
    summary = s.summary()
    assert summary["by_kind"]["http"] > 90 and summary["by_kind"]["cli"] >= 6 and summary["by_kind"]["job"] >= 3
    assert summary["unauthenticated_reaching_sink"] >= 20
    assert {"flask", "django", "drf", "fastapi", "express", "koa", "fastify", "nestjs", "nextjs", "spring", "jax-rs", "servlet",
            "aspnet", "aspnet-minimal", "net/http", "gin", "echo", "chi", "laravel", "symfony", "php", "rails",
            "sinatra"} <= set(summary["frameworks"])


def test_fingerprints_match_the_engine_and_supplied_findings_are_linked():
    from vulnscan import taint
    from vulnscan.model import assign_fingerprints
    root = DATA / "flask"
    files = {p.relative_to(root).as_posix(): p.read_text() for p in root.rglob("*.py")}
    findings = taint.analyze_project(files)
    assign_fingerprints(findings)
    engine_fps = {f.fingerprint() for f in findings}
    linked = {d["fingerprint"] for e in surf("flask").entries for d in e.findings}
    assert linked and linked <= engine_fps
    # findings handed over by a scan that already ran (JSON form): linked by location, no engine needed
    as_dicts = [f.to_dict() for f in findings]
    s = S.build_surface_from_files(files, findings=as_dicts, engine=False)
    users = [e for e in s.entries if e.path == "/users"][0]
    assert users.findings and users.findings[0]["direct"]                    # the flow starts in the handler (request.args)
    assert not users.sinks or users.sinks[0].origin != "model"               # ... but without the engine no call graph
    ping = [e for e in s.entries if e.path == "/ping"][0]
    assert ping.findings and ping.findings[0]["direct"] and ping.findings[0]["fingerprint"] in engine_fps
    assert any(sk.proven for sk in ping.sinks)
    projects, flows = taint.analyze_project_full(files)                      # models built by a scan are reused as they are
    assign_fingerprints(flows)
    s3 = S.build_surface_from_files(files, findings=flows, projects=projects)
    assert [(e.path, e.risk, [d["fingerprint"] for d in e.findings]) for e in s3.entries] == \
        [(e.path, e.risk, [d["fingerprint"] for d in e.findings]) for e in surf("flask").entries]
    s2 = S.build_surface_from_files(files, findings=[])                      # an explicit empty list: nothing is proven
    assert not any(e.findings for e in s2.entries) and any(e.sinks for e in s2.entries)


def test_no_engine_mode_uses_textual_patterns():
    s = surf("express", engine=False)
    assert s.notes and "disabled" in s.notes_text()[0] and "عُطِّل" in s.notes_text("ar")[0]
    search = [e for e in s.entries if e.path == "/api/users/search"][0]
    assert search.sinks and search.sinks[0].origin == "pattern" and search.sinks[0].category == "sql" and not search.findings
    assert search.risk_level == "high"                                       # unauthenticated + sink, nothing proven
    ping = [e for e in s.entries if e.path == "/api/users/ping"][0]
    assert not ping.sinks                                                    # the sink is one call away: needs the call graph


def test_openapi_path_normalisation():
    cases = {"/users/<int:id>": "/users/{id}", "/users/:id": "/users/{id}", "/files/*path": "/files/{path}",
             "/a/{id:[0-9]+}/b": "/a/{id}/b", "/api/users/[id]": "/api/users/{id}", "/docs/[...slug]": "/docs/{slug}",
             "export/(?P<fmt>\\w+)/": "/export/{fmt}/", "/x/{id?}": "/x/{id}", "/static/*": "/static/{wildcard}",
             "/a/:id/b/:id": "/a/{id}/b/{id2}", "items": "/items", "/photos/{photo}": "/photos/{photo}"}
    for raw, want in cases.items():
        assert S.openapi_path(raw) == want, raw


def test_openapi_document_is_structurally_valid():
    seen_ops = set()
    for name in ALL:
        doc = json.loads(S.render_openapi(surf(name), server_url="http://127.0.0.1:8080"))
        assert doc["openapi"] == "3.1.0" and doc["info"]["title"] and doc["servers"] == [{"url": "http://127.0.0.1:8080"}]
        ids = []
        for path, item in doc["paths"].items():
            assert path.startswith("/") and not re.search(r"[<>:\[\]()^$\\]", path), path
            for method, op in item.items():
                assert method in ("get", "post", "put", "delete", "patch", "head", "options", "trace")
                ids.append(op["operationId"])
                assert op["responses"]["default"]["description"] and isinstance(op["security"], list)
                declared = {p["name"] for p in op.get("parameters", []) if p["in"] == "path"}
                assert declared == set(re.findall(r"\{(\w+)\}", path)), (name, path)
                for p in op.get("parameters", []):
                    assert p["in"] in ("path", "query", "header", "cookie") and (p["required"] is True) == (p["in"] == "path")
                    assert p["schema"] == {"type": "string"}
                if op["security"]:
                    assert "inferredAuth" in doc["components"]["securitySchemes"]
                    assert op["x-kashif-auth"]["status"] == "protected"
                assert op["x-kashif-risk"]["level"] in S._LEVELS
                if "requestBody" in op:
                    assert method in ("post", "put", "patch")
                    (ctype, body), = op["requestBody"]["content"].items()
                    assert ctype in ("application/json", "application/x-www-form-urlencoded", "multipart/form-data")
                    assert body["schema"]["type"] == "object"
        assert len(ids) == len(set(ids))
        seen_ops.update(ids)
    flask = json.loads(S.render_openapi(surf("flask")))
    assert "servers" not in flask
    ping = flask["paths"]["/ping"]["post"]
    assert ping["requestBody"]["content"]["application/x-www-form-urlencoded"]["schema"]["properties"] == {"host": {"type": "string"}}
    assert ping["security"] == [{"inferredAuth": []}] and ping["x-kashif-sinks"] == ["command"] and ping["x-kashif-findings"]
    assert flask["paths"]["/users"]["get"]["security"] == []
    upload = flask["paths"]["/admin/import"]["post"]["requestBody"]["content"]["multipart/form-data"]["schema"]["properties"]
    assert upload == {"dump": {"type": "string", "format": "binary"}}
    assert "CatsController_remove" in " ".join(seen_ops)
    assert "لم يُرسَل أي طلب" in json.loads(S.render_openapi(surf("flask"), "ar"))["info"]["description"]


def test_markdown_csv_and_graph_outputs():
    s = surf("express")
    md = S.render_markdown(s)
    assert md.startswith("# Attack surface map") and "| # | Risk | Method |" in md and "no request was sent" in md
    assert md.count("\n| ") == len(s.entries) + 1                           # header + one row per entry
    assert "`/api/users/ping`" in md and "← runPing ✔" in md and "protected: requireAuth" in md
    assert md.index("/api/users/ping") < md.index("/api/admin/settings")
    assert S.render_markdown(s, top=0).count("### ") == 0 and md.count("### ") >= 4
    ar = S.render_markdown(s, "ar")
    assert ar.startswith("# خريطة سطح الهجوم") and "بلا مصادقة ظاهرة" in ar and "لا شيء ظاهر" in ar and "حرج" in ar
    rows = list(csv.DictReader(io.StringIO(S.render_csv(s))))
    assert len(rows) == len(s.entries) and rows[0]["rank"] == "1" and rows[0]["risk_level"] == "critical"
    assert rows[0]["path"] == "/api/users/ping" and rows[0]["params"] == "body:host" and rows[0]["sink_categories"] == "command"
    assert rows[0]["findings"] and rows[0]["auth_status"] == "none"
    mer = S.render_mermaid(s)
    assert mer.startswith("flowchart LR") and "e1 --> f1" in mer and "f1 --> s1" in mer and ":::unauth" in mer
    assert 'f1["runPing"]' in mer and "child_process.exec" in mer and "<anonymous>" not in mer
    dot = S.render_dot(s)
    assert dot.startswith("digraph attack_surface {") and dot.rstrip().endswith("}") and "e1 -> f1;" in dot
    assert dot.count("{") == dot.count("}")
    assert "%%" in S.render_mermaid(S.build_surface(DATA), top=3) and S.render_mermaid(S.build_surface(DATA), top=3).count("([") == 3
    with pytest.raises(ValueError):
        S.render(s, "pdf")
    assert S.render(s, "md") == md and S.render(s, "graphviz") == dot


def test_csv_neutralises_spreadsheet_formulas():
    files = {"app.py": "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/=cmd|calc')\ndef x():\n    return ''\n",
             "nest.controller.ts": "@Controller('c')\nexport class C {\n  @Public()\n  @Get()\n  a() { return 1; }\n}\n"}
    rows = list(csv.reader(io.StringIO(S.render_csv(S.build_surface_from_files(files)))))
    cells = [c for r in rows[1:] for c in r]
    assert "'@Public()" in cells and not any(c and c[0] in "=+-@" for c in cells)


def test_strings_are_complete_in_both_languages():
    assert set(S.STR["en"]) == set(S.STR["ar"])
    for key, text in S.STR["en"].items():
        assert set(re.findall(r"\{(\w+)\}", text)) == set(re.findall(r"\{(\w+)\}", S.STR["ar"][key])), key
    assert all(re.search(r"[؀-ۿ]", v) or k in ("col_rank", "none", "kind_http") for k, v in S.STR["ar"].items())


def test_test_files_are_skipped_unless_asked():
    files = {"app.js": "const app = require('express')();\napp.get('/a', (req, res) => res.end());\n",
             "tests/app.test.js": "const app = require('express')();\napp.get('/only-in-test', (req, res) => res.end());\n"}
    assert [e.path for e in S.build_surface_from_files(files).entries] == ["/a"]
    assert {e.path for e in S.build_surface_from_files(files, include_tests=True).entries} == {"/a", "/only-in-test"}


def test_http_clients_and_lookups_are_not_routes():
    js = ("const axios = require('axios');\nconst cache = new Map();\n"
          "axios.get('/api/users', { params: { a: 1 } });\ncache.get('/key');\nclient.post('/x', body, cb);\n"
          "api.get('/remote', { headers });\n")
    go = ('package main\nimport "net/http"\nfunc f(q map[string]string) {\n\thttp.Get("/internal/x")\n'
          '\tviper.Get("/a/b")\n\tresp, _ := client.Post("/x", "text/plain", nil)\n\t_ = resp\n}\n')
    assert S.build_surface_from_files({"client.js": js, "c.go": go}).entries == []


def test_scanned_code_is_never_executed_and_no_network_is_used(tmp_path, monkeypatch):
    marker = tmp_path / "executed.txt"
    files = {"evil.py": f"import pathlib\npathlib.Path({str(marker)!r}).write_text('x')\n"
                        "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/x')\ndef x():\n    return ''\n",
             "evil.rb": f"File.write({str(marker)!r}, 'x')\nrequire 'sinatra'\nget '/y' do\n  'y'\nend\n"}

    def no_network(*a, **k):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    s = S.build_surface_from_files(files)
    assert {e.path for e in s.entries} == {"/x", "/y"} and not marker.exists()
    for fmt in S.FORMATS:
        S.render(s, fmt)


def test_hostile_and_broken_input_does_not_crash():
    junk = {
        "a.py": "def broken(:\n  pass\n", "b.js": "app.get('/x', (req, res) => { " + "{" * 500,
        "c.java": "@RestController public class X { @GetMapping(\"/a\" public String a( {{{ ", "d.cs": "[HttpGet(\"x\"] public class",
        "e.go": 'package main\nfunc main() { r.GET("/x", ', "f.php": "<?php Route::get('/x', function () { ",
        "g.rb": "get '/x' do\n", "config/routes.rb": "Rails.application.routes.draw do\n  resources :a do\n    member do\n",
        "h.kt": "@RestController class K { @GetMapping(\"/k\") fun k(", "i.ts": "@Controller('x') export class C { @Get(':id') f(@Param('id'",
        "j.py": "\x00\x01\x02 @app.route('/z')\n", "k.js": "/* unterminated " + "x" * 2000, "l.php": "<?php $_GET[",
        "m.py": "from django.urls import path\nurlpatterns = [path('a/', missing.view), path('b/', include('nowhere.urls'))]\n",
        "WEB-INF/web.xml": "<web-app><servlet><servlet-name>x", "config/packages/security.yaml": "access_control:\n  - { path: ^/(, roles: X }\n",
    }
    s = S.build_surface_from_files(junk)
    for fmt in S.FORMATS:
        assert S.render(s, fmt)
    assert S.build_surface_from_files({}).entries == []
    empty = S.render_markdown(S.build_surface_from_files({}))
    assert "No entry point was recognised" in empty
    assert json.loads(S.render_openapi(S.build_surface_from_files({})))["paths"] == {}
    assert S.render_mermaid(S.build_surface_from_files({})).startswith("flowchart LR")


def test_command_line(tmp_path, capsys):
    assert S.main([str(DATA / "flask")]) == 0
    out = capsys.readouterr().out
    assert out.startswith("# Attack surface map") and "`/greet/<name>`" in out
    assert S.main([str(DATA / "flask"), "-f", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["summary"]["by_kind"]["http"] == 7 and doc["entries"][0]["risk_level"] == "critical"
    assert doc["entries"][0]["openapi_path"].startswith("/") and doc["entries"][0]["unauthenticated"] is True
    target = tmp_path / "api.json"
    assert S.main([str(DATA / "spring"), "-f", "openapi", "-o", str(target), "--server-url", "https://staging.example"]) == 0
    captured = capsys.readouterr()
    assert captured.out == "" and "written" in captured.err
    assert json.loads(target.read_text(encoding="utf-8"))["servers"][0]["url"] == "https://staging.example"
    assert S.main([str(DATA / "flask"), "-f", "markdown", "--lang", "ar", "--top", "0"]) == 0
    assert capsys.readouterr().out.startswith("# خريطة سطح الهجوم")
    assert S.main([str(DATA / "flask"), "--fail-on-unauth-sink", "-f", "csv"]) == 1
    capsys.readouterr()
    assert S.main([str(DATA / "symfony" / "config"), "--fail-on-unauth-sink"]) == 0           # nothing reachable: gate passes
    capsys.readouterr()
    assert S.main([str(DATA / "express"), "--no-engine", "--exclude", "routes/*", "-f", "csv"]) == 0
    rows = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    assert {r["path"] for r in rows} == {"/health", "/login"}
    assert S.main([str(tmp_path / "missing")]) == 2
    assert "path not found" in capsys.readouterr().err
    assert S.main([str(tmp_path / "missing"), "--lang", "ar"]) == 2
    assert "المسار غير موجود" in capsys.readouterr().err
    assert S.main(["--format", "nope", "x"]) == 2
    capsys.readouterr()
    assert S.main([str(DATA / "flask" / "app.py"), "-f", "csv"]) == 0                         # a single file works too
    assert "/users" in capsys.readouterr().out


def test_module_runs_with_dash_m():
    import subprocess
    import sys
    root = pathlib.Path(__file__).resolve().parent.parent
    proc = subprocess.run([sys.executable, "-m", "vulnscan.surface", str(DATA / "gin"), "-f", "mermaid"], cwd=root,
                          capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert proc.returncode == 0 and proc.stdout.startswith("flowchart LR") and "GET /download" in proc.stdout


# ------------------------------------------------------------------------------------------ adversarial review fixes
def _build(files, **kw):
    kw.setdefault("engine", False)
    return S.build_surface_from_files(files, **kw)


def _status(s):
    return {(e.method, e.path): e.auth["status"] for e in s.entries}


def test_hostile_input_is_linear_time():
    """Unclosed / deeply nested route DSLs used to cost quadratic time (minutes for one 300 kB file)."""
    import time
    n = 20000
    cases = {
        "a.js": "app.get(" * n,
        "b.js": "const app = require('express')();\n" + "app.get('/x', function(req,res){" * n,
        "main.go": "package main\nfunc main(){\n" + "r.GET(\"/a\", func(c *gin.Context){\n" * n,
        "P.cs": "var app = b.Build();\n" + "app.MapGet(\"/a\", (" * n,
        "routes/web.php": "<?php\n" + "Route::prefix('p')->group(function () {\n" * n + "Route::get('/r', [C::class, 'm']);\n" + "});\n" * n,
        "config/routes.rb": "Rails.application.routes.draw do\n" + "namespace :a do\n" * n,
        "WEB-INF/web.xml": "<servlet-mapping>" * n + "<!--" * n,
        "config/packages/security.yaml": "access_control:\n" + "  - { path: ^/a" * n,
        "A.java": "class A extends HttpServlet { void doGet(HttpServletRequest r, HttpServletResponse s){} }",
        "c.php": "<?php #[Route('/a')] function a(){}",
    }
    start = time.monotonic()
    s = _build(cases)
    for fmt in S.FORMATS:
        assert S.render(s, fmt)
    assert time.monotonic() - start < 30          # about 2 s on a laptop; it never finished before
    assert not [n for n in s.notes_text() if "extractor failed" in n]


def test_bracket_table_matches_the_plain_scan():
    text = "f(a, [b, {c}], (d)) " * 40 + "g(((" + ")" + " tail(x)"
    assert len(text) > 512
    for i, ch in enumerate(text):
        if ch in "([{":
            depth, want = 0, -1
            for j in range(i, len(text)):
                depth += text[j] in "([{"
                depth -= text[j] in ")]}"
                if depth == 0:
                    want = j
                    break
            assert S._close(text, i) == want
    assert S._close(text, len(text) + 5) == -1
    assert [text[a:b].strip() for a, b in S._split_top("f(a, [b, {c}], (d))", 2, 18)] == ["a", "[b, {c}]", "(d)"]


def test_entry_cap_and_skipped_file_notes(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "MAX_ENTRIES", 50)
    rb = "Rails.application.routes.draw do\n" + "".join(f"resources :r{i}\n" for i in range(40)) + "end\n"
    s = _build({"config/routes.rb": rb})
    assert len(s.entries) == 50 and any("50" in n for n in s.notes_text()) and any("50" in n for n in s.notes_text("ar"))
    monkeypatch.setattr(S, "MAX_SOURCE_BYTES", 200)
    (tmp_path / "big.py").write_text("# " + "x" * 400 + "\n", encoding="utf-8")
    (tmp_path / "ok.py").write_text("from flask import Flask\napp = Flask(__name__)\n@app.route('/a')\ndef a(): return ''\n", encoding="utf-8")
    s = S.build_surface(tmp_path, engine=False)
    assert [e.path for e in s.entries] == ["/a"] and any("1 source file" in n for n in s.notes_text())
    s = _build({"bad.py": "def (:\n", "ok.py": "x = 1\n"})
    assert any("bad.py" in n for n in s.notes_text())


def test_names_that_look_like_auth_but_do_not_enforce_it():
    for name in ("passport.initialize()", "passport.session()", "helmet.contentSecurityPolicy()", "referrerPolicy", "authLimiter",
                 "loginLimiter", "protect_from_forgery", "authenticationErrorHandler", "login_manager.user_loader", "authLogger",
                 "csrfProtection", "oauth.authorize_redirect"):
        assert S._guard(name, "middleware") is None, name
    for name in ("jwt_required(optional=True)", "jwt_optional", "auth.optional", "expressjwt({credentialsRequired: false})",
                 'PreAuthorize("permitAll()")', "AllowAnonymous", "permitAll"):
        assert S._guard(name, "x")[2] is True, name
    for name in ("jwt_required()", "login_required", "auth:sanctum", "requireAuth", "passport.authenticate('jwt')",
                 "PreAuthorize(\"hasRole('ADMIN')\")", "authenticate_user!", "auth.required", "get_current_user"):
        assert S._guard(name, "x")[2] is False, name


def test_express_prefix_scoped_and_ordered_middleware():
    s = _build({"app.js": """
const express = require('express'); const app = express();
app.get('/open', (req, res) => res.send(req.query.a));
app.use(passport.initialize());
app.get('/greeting', (req, res) => res.send(req.user ? req.user.name : 'guest'));
app.use('/admin', requireAuth);
app.get('/admin/x', (req, res) => res.send('x'));
app.get('/administrator', (req, res) => res.send('x'));
app.get('/other', (req, res) => res.send('x'));
app.get('/me', (req, res) => { if (!req.user) return res.status(401).end(); res.send('x'); });
app.use(requireAuth);
app.get('/late', (req, res) => res.send('x'));
"""})
    st = _status(s)
    assert st[("GET", "/admin/x")] == "protected" and st[("GET", "/late")] == "protected" and st[("GET", "/me")] == "protected"
    # reading req.user is not a check; a guard mounted on /admin does not cover /other or /administrator
    for path in ("/open", "/greeting", "/administrator", "/other"):
        assert st[("GET", path)] == "none", path


def test_optional_and_read_only_auth_is_reported_public():
    s = _build({"a.py": """
from flask import Flask, request
from flask_jwt_extended import jwt_required
from werkzeug.security import check_password_hash
app = Flask(__name__)
@app.route('/login', methods=['POST'])
def login():
    return str(check_password_hash(h, request.form['password']))
@app.route('/opt')
@jwt_required(optional=True)
def opt(): return ''
@app.route('/req')
@jwt_required()
def req(): return ''
@app.route('/hello')
def hello():
    return current_user.is_authenticated and 'hi' or 'guest'
""", "v.py": """
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from django.urls import path
class A(APIView):
    permission_classes = [IsAuthenticatedOrReadOnly]
    def get(self, request): return 1
urlpatterns = [path('a/', A.as_view())]
"""})
    st = {e.path: e.auth["status"] for e in s.entries}
    assert st["/opt"] == "public" and st["/req"] == "protected"
    assert st["/login"] == "none" and st["/hello"] == "none"          # a login form is not behind authentication
    assert st["/a/"] == "public"


def test_spring_multiple_paths_and_permit_all_expression():
    s = _build({"C.java": """
@RestController @RequestMapping({"/api", "/v2"})
public class C {
  @PreAuthorize("permitAll()") @GetMapping("/other") public String c() { return ""; }
  @PostMapping(path = {"/m1", "/m2"}) public String d(@RequestBody Dto d) { return ""; }
  @GetMapping public String e() { return ""; }
  @RequestMapping(value = "/f", method = RequestMethod.GET) public String f() { return ""; }
}"""})
    st = _status(s)
    assert {p for _m, p in st} == {"/api", "/v2", "/api/f", "/v2/f", "/api/m1", "/api/m2", "/v2/m1", "/v2/m2", "/api/other", "/v2/other"}
    assert st[("GET", "/api/other")] == "public" and st[("POST", "/v2/m2")] == "none"


def test_ant_matcher_and_project_supplied_regex_are_safe():
    for pat, path, want in [("/admin/**", "/admin", True), ("/admin/**", "/admin/x/y", True), ("/admin/*", "/admin/x/y", False),
                            ("/admin/*", "/admin/x", True), ("/**", "/a/b", True), ("/api/*/users", "/api/v1/users", True),
                            ("/a/**/z", "/a/z", True), ("/a/**/z", "/a/b/c/z", True), ("/*.html", "/x.html", True),
                            ("/a?c", "/abc", True), ("/admin", "/admins", False)]:
        assert S._ant_match(pat, path) is want, (pat, path)
    import time
    start = time.monotonic()
    assert S._ant_match("/" + "**/" * 30 + "x", "/" + "a/" * 60 + "y") is False
    assert S._ant_match("/" + "*a" * 40, "/" + "a" * 150 + "b") is False
    assert S._safe_regex("^/admin") and S._safe_regex("^/(en|fr)/admin") and S._safe_regex("^/api/(?!login)")
    assert not S._safe_regex("^/(a+)+$") and not S._safe_regex(".*.*.*.*x") and not S._safe_regex("^/(a|aa)*$")
    s = _build({"src/C.php": "<?php\nclass C {\n #[Route('/" + "a" * 40 + "!')]\n public function a() {}\n"
                             " #[Route('/admin/users')]\n public function b() {}\n}\n",
                "config/packages/security.yaml": "security:\n    access_control:\n        - { path: ^/(a+)+$, roles: ROLE_X }\n"
                                                 "        - { path: /admin, roles: ROLE_ADMIN }\n"})
    assert time.monotonic() - start < 5
    st = {e.path: e.auth["status"] for e in s.entries}
    assert st["/admin/users"] == "protected" and st["/" + "a" * 40 + "!"] == "none"


def test_openapi_path_conversions_follow_each_framework():
    for src, want in [("/files/{path...}", "/files/{path}"), ("/{$}", "/"), ("/items/{id}/{$}", "/items/{id}/"),
                      ("/a/{id<\\d+>}", "/a/{id}"), ("/a/{!page}", "/a/{page}"), ("/a/{page<\\d+>?1}", "/a/{page}"),
                      ("/a/:from-:to", "/a/{from}-{to}"), ("/posts/:id(.:format)", "/posts/{id}"), ("/a/{id:int}", "/a/{id}"),
                      ("/a/{*slug}", "/a/{slug}"), ("/api/[[...slug]]", "/api/{slug}"), ("<int:pk>/", "/{pk}/"),
                      ("^articles/(?P<year>[0-9]{4})/$", "/articles/{year}/"), ("/a/:id(\\d+)", "/a/{id}")]:
        assert S.openapi_path(src) == want, src
    s = _build({"main.go": """package main
import "net/http"
func main() {
  mux := http.NewServeMux()
  mux.HandleFunc("POST /items/{id}", item)
  mux.HandleFunc("GET /files/{path...}", item)
  mux.HandleFunc("/{$}", item)
}
func item(w http.ResponseWriter, r *http.Request) { _ = r.PathValue("id") }
""", "u.py": "from django.urls import re_path\nfrom . import v\nurlpatterns = [re_path(r'^a/(\\d+)/$', v.x)]\n",
                "v.py": "def x(request, n): return n\n"})
    doc = json.loads(S.render_openapi(s))
    assert set(doc["paths"]) == {"/items/{id}", "/files/{path}", "/"}
    assert doc["x-kashif-skipped-paths"]                       # the unnamed regex group is not a path template
    for path, item in doc["paths"].items():
        assert re.fullmatch(r"/(?:[^{}\s?#]|\{\w+\})*", path)
        for op in item.values():
            declared = {p["name"] for p in op.get("parameters", []) if p["in"] == "path"}
            assert declared == set(re.findall(r"\{(\w+)\}", path))


def test_openapi_operation_ids_are_unique():
    files = {"app.js": "const app = require('express')();\n" + "".join(
        f"app.get('/r{i}', h);\napp.get('/q{i}', h_2);\n" for i in range(4)) + "function h(req,res){}\nfunction h_2(req,res){}\n"}
    doc = json.loads(S.render_openapi(_build(files)))
    ids = [op["operationId"] for item in doc["paths"].values() for op in item.values()]
    assert len(ids) == 8 and len(set(ids)) == 8


def test_reports_neutralise_hostile_names():
    evil_file = "a|b`<img src=x onerror=alert(1)>‮[x](javascript:1).py"
    src = "from flask import Flask, request\nimport os\napp = Flask(__name__)\n" \
          "@app.route('/x|y`z<b>\"]')\ndef h():\n    os.system(request.args.get('=cmd|calc'))\n    return ''\n"
    s = _build({evil_file: src})
    assert len(s.entries) == 1
    md = S.render_markdown(s)
    assert "<img" not in md and "<b>" not in md.replace("`/x\\|y'z<b>\"]`", "") and "‮" not in md
    table_rows = [ln for ln in md.splitlines() if ln.startswith("| 1 ")]
    assert len(table_rows) == 1 and len(re.findall(r"(?<!\\)\|", table_rows[0])) == 13       # 12 cells, none forged
    assert "[x](javascript" not in md
    rows = list(csv.reader(io.StringIO(S.render_csv(s))))
    assert len(rows) == 2 and all(not c.lstrip().startswith(("=", "+", "-", "@")) for c in rows[1])
    assert S._csv_cell("  =1+1").startswith("'") and S._csv_cell("-2+3").startswith("'") and S._csv_cell(7) == "7"
    mer = S.render_mermaid(s)
    assert '"]' not in re.sub(r'\["[^"]*"\]|\(\["[^"]*"\]\)|\{\{"[^"]*"\}\}', "", mer) and "‮" not in mer
    for line in mer.splitlines():
        assert line.count('"') in (0, 2)
    dot = S.render_dot(s)
    assert "‮" not in dot and all(ln.count('"') % 2 == 0 for ln in dot.replace('\\"', "").splitlines())
    json.loads(S.render_json(s))
    json.loads(S.render_openapi(s))


def test_findings_in_dict_form_are_not_trusted():
    src = {"a.py": "from flask import Flask, request\nimport os\napp = Flask(__name__)\n"
                   "@app.route('/x')\ndef h():\n    os.system(request.args.get('c'))\n    return ''\n"}
    junk = [None, {}, {"extra": "x"}, {"extra": {"path": "nope"}}, {"extra": {"path": [None, 3, {"line": "seven"}]}, "line": "6"},
            {"rule_id": None, "file": None, "line": None, "title": None, "cwe": None, "extra": {"analysis": "taint"}},
            {"rule_id": "DF1", "file": "a.py", "line": "6", "severity": "high", "cwe": "CWE-78", "title": "cmd", "fingerprint": 12,
             "extra": {"path": [{"file": "a.py", "line": 6.0}]}},
            {"rule_id": "DF2", "file": "a.py", "line": 6, "severity": "high", "cwe": "CWE-78", "title": "t", "fingerprint": "f" * 16,
             "extra": {"analysis": "dataflow", "path": [{"file": "a.py", "line": 10 ** 400}]}}]
    s = _build(src, findings=junk)
    e = s.entries[0]
    assert {d["rule"] for d in e.findings} >= {"DF1", "DF2"} and e.risk_level == "critical"
    for fmt in S.FORMATS:
        assert S.render(s, fmt)
    assert _build(src, findings=[]).entries[0].findings == []


def test_guard_arguments_never_leak_a_long_literal():
    literal = "".join(chr(97 + (i * 7) % 26) for i in range(32))            # built at run time: not a real key
    s = _build({"app.js": "const app = require('express')();\n"
                          f"app.get('/k', apiKeyAuth('{literal}'), (req, res) => res.send('x'));\n"
                          "app.get('/r', requireRole('admin'), (req, res) => res.send('x'));\n"})
    text = "".join(S.render(s, fmt) for fmt in S.FORMATS)
    assert literal not in text and "apiKeyAuth" in text and "requireRole('admin')" in S.render_json(s)


def test_windows_style_paths_and_output_errors(tmp_path, capsys):
    s = _build({"pkg\\app.py": "from flask import Flask\napp = Flask(__name__)\n@app.route('/a')\ndef a(): return ''\n"})
    assert [(e.path, e.file) for e in s.entries] == [("/a", "pkg/app.py")]
    assert S.main([str(DATA / "flask"), "--no-engine", "-o", str(tmp_path / "missing" / "dir" / "out.md")]) == 2
    assert "cannot write" in capsys.readouterr().err
    out = tmp_path / "s.md"
    assert S.main([str(DATA / "flask"), "--no-engine", "--lang", "ar", "-o", str(out)]) == 0
    assert "\r" not in out.read_bytes().decode("utf-8") and "سطح الهجوم" in out.read_text(encoding="utf-8")
