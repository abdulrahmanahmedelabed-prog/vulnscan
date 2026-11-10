// expect-none: DF005
package main

import (
	"strconv"

	"github.com/labstack/echo/v4"
)

func report(c echo.Context) error {
	id, _ := strconv.Atoi(c.QueryParam("id"))
	return c.Attachment("/reports/"+strconv.Itoa(id)+".pdf", "report.pdf")
}
