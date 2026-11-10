// expect-none: DF010
package main

import (
	"net/http"
)

var backends = map[string]string{"eu": "https://eu.api.example.com/v1", "us": "https://us.api.example.com/v1"}

func fetch(w http.ResponseWriter, r *http.Request) {
	region := r.URL.Query().Get("region")
	target := "https://us.api.example.com/v1"
	if region == "eu" {
		target = "https://eu.api.example.com/v1"
	}
	req, _ := http.NewRequest("GET", target, nil)
	http.DefaultClient.Do(req)
}
