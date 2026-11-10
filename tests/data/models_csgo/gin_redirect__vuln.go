// expect: DF008
package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func login(c *gin.Context) {
	next := c.Query("next")
	c.Redirect(http.StatusFound, next)
}
