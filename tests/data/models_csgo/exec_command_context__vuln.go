// expect: DF003
package main

import (
	"net/http"
	"os/exec"
)

func ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	exec.CommandContext(r.Context(), "sh", "-c", "ping -c 1 "+host).Run()
}
