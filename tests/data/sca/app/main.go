package main

import (
	"fmt"

	"golang.org/x/text/language"
)

func main() {
	tag, _ := language.ParseAcceptLanguage("en")
	fmt.Println(tag)
}
