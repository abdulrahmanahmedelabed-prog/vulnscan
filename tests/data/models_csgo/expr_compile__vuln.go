// expect: DF012
package main

import (
	"net/http"

	"github.com/expr-lang/expr"
)

func rule(w http.ResponseWriter, r *http.Request) {
	program, _ := expr.Compile(r.FormValue("rule"))
	expr.Run(program, nil)
}
