// expect-none: DF012
#include <fcgiapp.h>
#include <lauxlib.h>
#include <lua.h>

void run_rule(FCGX_Request *request, lua_State *L) {
    const char *rule = FCGX_GetParam("HTTP_X_RULE", request->envp);
    lua_pushstring(L, rule);
    lua_setglobal(L, "rule_name");
    luaL_dostring(L, "return apply(rule_name)");
}
