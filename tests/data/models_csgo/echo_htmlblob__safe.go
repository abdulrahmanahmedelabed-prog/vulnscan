// expect-none: DF013
package main

import (
	"github.com/labstack/echo/v4"
)

var banner = "<h1>Preview</h1>"

func preview(c echo.Context) error {
	c.HTMLBlob(200, banner)
	return nil
}
