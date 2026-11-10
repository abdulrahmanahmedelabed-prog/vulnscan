// expect-none: DF012 DF015
package main

import (
	"net/http"
	"strconv"

	"github.com/expr-lang/expr"
)

func rule(w http.ResponseWriter, r *http.Request) {
	price, _ := strconv.Atoi(r.FormValue("price"))
	program, _ := expr.Compile("price > 100")
	expr.Run(program, price)
}
