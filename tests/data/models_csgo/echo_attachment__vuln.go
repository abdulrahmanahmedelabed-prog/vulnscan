// expect: DF005
package main

import (
	"github.com/labstack/echo/v4"
)

func report(c echo.Context) error {
	return c.Attachment("/reports/"+c.QueryParam("id"), "report.pdf")
}
