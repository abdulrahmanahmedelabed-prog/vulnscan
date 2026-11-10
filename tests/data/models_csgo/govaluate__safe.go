// expect-none: DF012
package main

import (
	"net/http"

	"github.com/Knetic/govaluate"
)

func evaluate(w http.ResponseWriter, r *http.Request) {
	e, _ := govaluate.NewEvaluableExpression("total * 1.2")
	e.Evaluate(nil)
}
