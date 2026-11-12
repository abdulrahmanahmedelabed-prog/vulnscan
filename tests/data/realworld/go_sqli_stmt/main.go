package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

var DB *sql.DB

type Profile struct{ Name string }

func (p *Profile) UnsafeGet(uid string) error {
	q := fmt.Sprintf(`SELECT name
		FROM profile
		WHERE id=%s`, uid)
	rows, err := DB.Query(q)
	if err != nil {
		return err
	}
	defer rows.Close()
	return nil
}

func (p *Profile) SafeGet(uid string) error {
	stmt, err := DB.Prepare("SELECT name FROM profile WHERE id=?")
	if err != nil {
		return err
	}
	defer stmt.Close()
	return stmt.QueryRow(uid).Scan(&p.Name)
}

func unsafeHandler(w http.ResponseWriter, r *http.Request) {
	p := &Profile{}
	p.UnsafeGet(r.FormValue("uid"))
}

func safeHandler(w http.ResponseWriter, r *http.Request) {
	p := &Profile{}
	p.SafeGet(r.FormValue("uid"))
}

func main() {
	http.HandleFunc("/u", unsafeHandler)
	http.HandleFunc("/s", safeHandler)
	http.ListenAndServe(":8080", nil)
}
