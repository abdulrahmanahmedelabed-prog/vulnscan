// expect-none: DF004
package main

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

var db *gorm.DB

type User struct{ Name string }

func show(c *gin.Context) {
	var u User
	db.First(&u, "name = ?", c.Query("name"))
}
