// expect-none: DF012
package main

import (
	"net/http"

	"github.com/robertkrimen/otto"
)

func calc(w http.ResponseWriter, r *http.Request) {
	vm := otto.New()
	vm.Set("input", r.FormValue("value"))
	vm.Run("result = input.length")
}
