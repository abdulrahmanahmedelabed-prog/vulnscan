// expect: DF015
package main

import (
	"net/http"

	"github.com/antchfx/xmlquery"
)

var doc *xmlquery.Node

func user(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	xmlquery.Find(doc, "//user[name='"+name+"']")
}
