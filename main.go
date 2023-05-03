package main

import (

	// "html/template"
	"net/http"

	// "github.com/gorilla/mux"
	"example.com/jwt-demo/controller"
	"example.com/jwt-demo/model"
	"github.com/gorilla/mux"
	// "github.com/lib/pq"
	// "example.com/jwt-demo/controller"
)




func main() {
	model.Connect()
	r := mux.NewRouter()

	r.HandleFunc("/signup",controller.SignupHandler).Methods("GET")
	r.HandleFunc("/signup",controller.SignUp).Methods("POST")
	
	r.HandleFunc("/", controller.LoginHandler).Methods("GET")
	r.HandleFunc("/",controller.Login).Methods("POST")
	
	r.HandleFunc("/home",controller.HomeHandler).Methods("GET")

	r.HandleFunc("/adminpanel",controller.AdminPanel).Methods("GET")
	r.HandleFunc("/adminpanel",controller.AddUser).Methods("POST")

	r.HandleFunc("/delete",controller.DeleteUser).Methods("GET")
	
	r.HandleFunc("/update",controller.UpdateUser).Methods("GET")
	r.HandleFunc("/update",controller.UpdateUserReal).Methods("POST")

	r.HandleFunc("/logout",controller.Logout).Methods("GET")

	http.ListenAndServe(":8080", r)


	
}

