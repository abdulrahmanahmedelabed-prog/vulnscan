// expect: DF015
#include <fcgiapp.h>
#include <glib.h>
#include <libxml/xpath.h>

void find_book(FCGX_Request *request, xmlXPathContextPtr ctx) {
    const char *isbn = FCGX_GetParam("HTTP_X_ISBN", request->envp);
    char *expr = g_strdup_printf("//book[isbn='%s']/title", isbn);
    xmlXPathObjectPtr hits = xmlXPathEvalExpression(expr, ctx);
    xmlXPathFreeObject(hits);
}
