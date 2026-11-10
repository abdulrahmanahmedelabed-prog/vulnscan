// expect: DF005
package main

import (
	"github.com/gin-gonic/gin"
)

func upload(c *gin.Context) {
	file, _ := c.FormFile("avatar")
	c.SaveUploadedFile(file, "/var/uploads/"+file.Filename)
}
