package main

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("Authorization") == "" {
			c.AbortWithStatus(401)
		}
	}
}

func download(c *gin.Context) {
	data, _ := os.ReadFile("/srv/files/" + c.Query("file"))
	c.Data(200, "application/octet-stream", data)
}

func fetch(c *gin.Context) {
	resp, _ := http.Get(c.PostForm("url"))
	c.JSON(200, resp.Status)
}

func main() {
	r := gin.Default()
	r.GET("/download", download)
	r.GET("/users/:id", func(c *gin.Context) {
		c.JSON(200, gin.H{"id": c.Param("id"), "trace": c.GetHeader("X-Trace")})
	})
	admin := r.Group("/admin", AuthRequired())
	admin.POST("/fetch", fetch)
	v1 := r.Group("/api/v1")
	v1.Use(AuthRequired())
	v1.DELETE("/items/:id", func(c *gin.Context) {
		c.Status(204)
	})
	r.Run()
}
