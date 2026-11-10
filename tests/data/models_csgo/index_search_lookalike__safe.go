// expect-none: DF014
package main

import (
	"fmt"
	"net/http"
)

type Index struct{}

func (i *Index) Search(query string) []string { return nil }

var idx = &Index{}

func search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	hits := idx.Search(q) // a full-text index, not LDAP
	fmt.Println(len(hits))
}
