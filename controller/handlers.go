package controller

import (
	// "database/sql"
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"time"

	"example.com/jwt-demo/model"
	"github.com/golang-jwt/jwt"
	_ "github.com/lib/pq"
)

// login GET HANDLER
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Create a new template with the name "home"

	// Execute the template with the PageData struct as input
	err := model.Tpl.ExecuteTemplate(w,"loginget.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

// signUP GET 
func SignupHandler(w http.ResponseWriter, req *http.Request) {
	err := model.Tpl.ExecuteTemplate(w,"signupget.html",nil )
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

//  Home Handler users

func HomeHandler(w http.ResponseWriter, r *http.Request) {

	// Parse the JWT token from the user's browser cookie or header.
	tokenString, err := r.Cookie("jwt")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Verify the token's signature.
	token, err := jwt.Parse(tokenString.Value, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret-key"), nil // Replace with your own secret key
	})
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Extract the user's identity from the token.
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	username := claims["username"].(string)

	// Check if the user is authorized to access the home page.
	permission := isAuthorized(w,username)
	
	if permission == "admin" {
		http.Redirect(w,r,"/",http.StatusSeeOther)
	} 

	model.Tpl.ExecuteTemplate(w,"userhomepage.html",nil)
}



func isAuthorized(w http.ResponseWriter,username string) string {
	// Check if the user is authorized to access the home page.

	// Prepare the SQL statement
sqlStatement := `SELECT permission FROM people WHERE username=$1`
row := model.DB.QueryRow(sqlStatement, username)

// Scan the row into variables
var permission string
err := row.Scan(&permission)
if err != nil {
    log.Fatal(err)
}

return permission
}


func Login(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
	}

	// Create new user from form data
	    user := model.People{
			Username : r.FormValue("username"),
			Password : r.FormValue("password"),
	}

	// #######

	sqlStatement := `SELECT username,password FROM people WHERE username=$1`
	row := model.DB.QueryRow(sqlStatement, user.Username)

	// Scan the row into variables
	var username,password string
	err = row.Scan(&username,&password)

	if err != nil {
    if err == sql.ErrNoRows {
			http.Redirect(w,r,"/",http.StatusSeeOther)
			return
		} 
	}

	if username != user.Username || password != user.Password {
		http.Redirect(w,r,"/",http.StatusSeeOther)
		return
	}

	// ########

	token := jwt.New(jwt.SigningMethodHS256)
  claims := token.Claims.(jwt.MapClaims)
  claims["username"] = user.Username
  claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

  // Generate signed token string
  tokenString, err := token.SignedString([]byte("secret-key"))
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }

  // Set JWT token in cookie
  http.SetCookie(w, &http.Cookie{
    Name:  "jwt",
    Value: tokenString,
    Path:  "/",
  })
	
	permission := isAuthorized(w,username)

	if permission == "user" {
		http.Redirect(w,r,"/home",http.StatusSeeOther)
		return
	}

	if permission == "admin" {
		http.Redirect(w,r,"adminpanel",http.StatusSeeOther)
		return
	}
}


func SignUp(w http.ResponseWriter, r *http.Request) {
	// Parse form data
	err := r.ParseForm()
	if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
	}

	// Create new user from form data
	user := model.People{
			Name:  r.FormValue("name"),
			Username : r.FormValue("username"),
			Password : r.FormValue("password"),
			Permission: "user",
	}

	// Insert new user into database
	stmt, err := model.DB.Prepare("INSERT INTO people (name, username, password, permission) VALUES ($1, $2, $3, $4)")
	if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
	}
	defer stmt.Close()

	_, err = stmt.Exec(user.Name, user.Username, user.Password, user.Permission)
	if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
	}

	token := jwt.New(jwt.SigningMethodHS256)
  claims := token.Claims.(jwt.MapClaims)
  claims["username"] = user.Username
  claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

  // Generate signed token string
  tokenString, err := token.SignedString([]byte("secret-key"))
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }

  // Set JWT token in cookie
  http.SetCookie(w, &http.Cookie{
    Name:  "jwt",
    Value: tokenString,
    Path:  "/",
  })

		
		 http.Redirect(w,r,"/home",http.StatusSeeOther)
	// w.WriteHeader(http.StatusCreated)


}



func AdminPanel(w http.ResponseWriter, r *http.Request) {

	// Parse the JWT token from the user's browser cookie or header.
	tokenString, err := r.Cookie("jwt")
	if err != nil {
		fmt.Println("error in line 44")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Verify the token's signature.
	token, err := jwt.Parse(tokenString.Value, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret-key"), nil // Replace with your own secret key
	})
	if err != nil {
		fmt.Println("error in line 54")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Extract the user's identity from the token.
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		fmt.Println("error in line 62")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	username := claims["username"].(string)

	if username == "user" {
		http.Redirect(w,r,"/HomeHandler",http.StatusSeeOther)
		return
	}

	model.Tpl.ExecuteTemplate(w,"adminhomepage.html",nil)


}