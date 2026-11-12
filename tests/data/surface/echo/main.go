package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
	echojwt "github.com/labstack/echo-jwt/v4"
)

func redirect(c echo.Context) error {
	return c.Redirect(http.StatusFound, c.QueryParam("next"))
}

func saveNote(c echo.Context) error {
	return c.String(200, c.FormValue("text"))
}

func main() {
	e := echo.New()
	e.GET("/go", redirect)
	g := e.Group("/notes")
	g.Use(echojwt.JWT([]byte("k")))
	g.POST("/:id", saveNote)
	e.Start(":8080")
}
