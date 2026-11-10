// expect: DF004
package main

import (
	"io"
	"net/http"

	"go.mongodb.org/mongo-driver/bson"
)

func query(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var filter bson.M
	bson.UnmarshalExtJSON(body, true, &filter)
}
