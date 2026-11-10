// expect-none: DF004
package main

import (
	"net/http"

	"xorm.io/xorm"
)

var engine *xorm.Engine

type User struct{ Name string }

func users(w http.ResponseWriter, r *http.Request) {
	var list []User
	engine.SQL("SELECT * FROM user WHERE name = ?", r.FormValue("name")).Find(&list)
}
