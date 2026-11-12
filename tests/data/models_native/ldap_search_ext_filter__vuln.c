// expect: DF014
#include <fcgiapp.h>
#include <glib.h>
#include <ldap.h>

void lookup(FCGX_Request *request, LDAP *ld) {
    const char *uid = FCGX_GetParam("HTTP_X_UID", request->envp);
    char *filter = g_strdup_printf("(&(objectClass=person)(uid=%s))", uid);
    LDAPMessage *result;
    ldap_search_ext_s(ld, "ou=people,dc=example,dc=org", LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL, NULL, NULL, 0, &result);
    g_free(filter);
}
