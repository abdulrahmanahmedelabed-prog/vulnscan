// expect: DF004
package main

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

var db *gorm.DB

func stats(c *gin.Context) {
	col := c.Query("by")
	var names []string
	db.Table("orders").Pluck(col, &names)
}
