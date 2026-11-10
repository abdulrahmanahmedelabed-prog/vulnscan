// expect: DF013
package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func hello(ctx echo.Context) error {
	name := ctx.QueryParam("name")
	return ctx.String(http.StatusOK, "<p>hello "+name+"</p>")
}
