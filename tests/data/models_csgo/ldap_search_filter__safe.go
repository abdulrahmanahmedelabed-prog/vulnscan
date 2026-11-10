// expect-none: DF014
package main

import (
	"net/http"

	"github.com/go-ldap/ldap/v3"
)

var conn *ldap.Conn

func lookup(w http.ResponseWriter, r *http.Request) {
	user := ldap.EscapeFilter(r.FormValue("user"))
	filter := "(&(objectClass=person)(uid=" + user + "))"
	req := ldap.NewSearchRequest("dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, nil, nil)
	conn.Search(req)
}
