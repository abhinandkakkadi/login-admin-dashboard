package model

import (
	"database/sql"
	"text/template"
)


type People struct {
	Username string 
	Name string
	Password string
	Permission string
}

type AdminDetails struct {
	Users []People
	AdminName string
}


var DB *sql.DB
func Connect() {
	var err error
	DB, err = sql.Open("postgres", "host=localhost port=5432 user=postgres password=132457689 dbname=users sslmode=disable")
	if err != nil {
			panic(err)
	}
	// defer DB.Close()

}

var Tpl *template.Template
func init() {
	Tpl = template.Must(template.ParseGlob("templates/*"))
}
