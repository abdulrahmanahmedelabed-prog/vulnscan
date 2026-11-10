// expect: DF013
package main

import (
	"io"

	"github.com/labstack/echo/v4"
)

func preview(c echo.Context) error {
	body, _ := io.ReadAll(c.Request().Body)
	c.HTMLBlob(200, body)
	return nil
}
