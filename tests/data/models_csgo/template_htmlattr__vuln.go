// expect: DF007
package main

import (
	"html/template"
	"net/http"
)

var page = template.Must(template.New("p").Parse(`<div {{.}}>hi</div>`))

func render(w http.ResponseWriter, r *http.Request) {
	attr := template.HTMLAttr(r.FormValue("attr"))
	page.Execute(w, attr)
}
