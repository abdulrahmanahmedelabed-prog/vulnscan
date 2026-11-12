// expect-none: DF015
#include <fcgiapp.h>
#include <libxml/xpath.h>

void find_book(FCGX_Request *request, xmlXPathContextPtr ctx) {
    const char *isbn = FCGX_GetParam("HTTP_X_ISBN", request->envp);
    xmlXPathObjectPtr hits = xmlXPathEvalExpression("//book/title", ctx);
    xmlXPathFreeObject(hits);
}
