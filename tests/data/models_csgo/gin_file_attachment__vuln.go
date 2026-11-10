// expect: DF005
package main

import (
	"github.com/gin-gonic/gin"
)

func export(c *gin.Context) {
	name := c.Param("name")
	c.FileAttachment("/var/exports/"+name, "export.csv")
}
