// expect: DF012
package main

import (
	"net/http"

	"github.com/robertkrimen/otto"
)

func calc(w http.ResponseWriter, r *http.Request) {
	vm := otto.New()
	vm.Run(r.FormValue("script"))
}
