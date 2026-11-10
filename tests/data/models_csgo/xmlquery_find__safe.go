// expect-none: DF015
package main

import (
	"net/http"

	"github.com/antchfx/xmlquery"
)

var doc *xmlquery.Node

func user(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	for _, n := range xmlquery.Find(doc, "//user") {
		if n.SelectAttr("name") == name {
			w.WriteHeader(200)
		}
	}
}
