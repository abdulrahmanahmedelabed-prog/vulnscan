// expect: DF010
package main

import (
	"net/http"
)

func hook(w http.ResponseWriter, r *http.Request) {
	callback := r.PostFormValue("callback")
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, callback, nil)
	http.DefaultClient.Do(req)
}
