// expect-none: DF008
package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func login(c *gin.Context) {
	next := "/dashboard"
	if c.Query("next") == "settings" {
		next = "/settings"
	}
	c.Redirect(http.StatusFound, next)
}
