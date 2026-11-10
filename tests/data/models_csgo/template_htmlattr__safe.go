// expect-none: DF007
package main

import (
	"html/template"
	"net/http"
)

var page = template.Must(template.New("p").Parse(`<div class="{{.}}">hi</div>`))

func render(w http.ResponseWriter, r *http.Request) {
	cls := r.FormValue("class")
	page.Execute(w, cls)
}
