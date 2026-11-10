// expect-none: DF005
package main

import (
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func upload(c *gin.Context) {
	file, _ := c.FormFile("avatar")
	c.SaveUploadedFile(file, filepath.Join("/var/uploads", filepath.Base(file.Filename)))
}
