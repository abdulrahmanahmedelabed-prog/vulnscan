// expect-none: DF004
package main

import (
	"net/http"

	"go.mongodb.org/mongo-driver/bson"
)

var defaultFilter = `{"active": true}`

func query(w http.ResponseWriter, r *http.Request) {
	var filter bson.M
	bson.UnmarshalExtJSON(defaultFilter, true, &filter)
	filter["owner"] = r.FormValue("owner")
}
