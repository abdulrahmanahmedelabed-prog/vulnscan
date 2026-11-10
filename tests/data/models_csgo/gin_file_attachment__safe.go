// expect-none: DF005
package main

import (
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func export(c *gin.Context) {
	name := filepath.Base(c.Param("name"))
	c.FileAttachment(filepath.Join("/var/exports", name), "export.csv")
}
