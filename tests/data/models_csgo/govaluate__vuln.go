// expect: DF012
package main

import (
	"net/http"

	"github.com/Knetic/govaluate"
)

func evaluate(w http.ResponseWriter, r *http.Request) {
	e, _ := govaluate.NewEvaluableExpression(r.FormValue("formula"))
	e.Evaluate(nil)
}
