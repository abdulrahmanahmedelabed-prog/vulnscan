package main
import ("database/sql"; "net/http"; "os/exec")
var db *sql.DB
func save(w http.ResponseWriter, r *http.Request) {
    db.Exec("INSERT INTO jobs (cmd) VALUES ($1)", r.FormValue("cmd"))
}
func runJobs(w http.ResponseWriter, r *http.Request) {
    row := db.QueryRow("SELECT cmd FROM jobs WHERE id = 1")
    var c string
    row.Scan(&c)
    exec.Command("sh", "-c", c).Run()
}
