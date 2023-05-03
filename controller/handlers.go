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
	w.Header().Set("Cache-Control","no-cache, no-store, must-revalidate")
	// Create a new template with the name "home"
	 _, err := r.Cookie("jwt")
	if err == nil {
		middleWare(w,r)
		return
	}

	// Execute the template with the PageData struct as input
	err = model.Tpl.ExecuteTemplate(w,"loginget.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

// signUP GET 
func SignupHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control","no-cache, no-store, must-revalidate")
	_, err := r.Cookie("jwt")
	if err == nil {
		middleWare(w,r)
		return
	}
	err = model.Tpl.ExecuteTemplate(w,"signupget.html",nil )
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

//  Home Handler users

func middleWare(w http.ResponseWriter, r *http.Request) {
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
		  jwtCookie := &http.Cookie{
			Name:     "jwt",
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
	  }
	  http.SetCookie(w, jwtCookie)
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
	
	if permission == "user" {
		http.Redirect(w,r,"/home",http.StatusSeeOther)
		return
	}

	if permission == "admin" {
		http.Redirect(w,r,"/adminpanel",http.StatusSeeOther)
		return
	}
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control","no-cache, no-store, must-revalidate")
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
		  jwtCookie := &http.Cookie{
			Name:     "jwt",
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
	  }
	  http.SetCookie(w, jwtCookie)
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
		http.Redirect(w,r,"/adminpanel",http.StatusSeeOther)
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
	w.Header().Set("Cache-Control","no-cache, no-store, must-revalidate")
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
	w.Header().Set("Cache-Control","no-cache, no-store, must-revalidate")

	//  _, err := r.Cookie("jwt")
	// if err == nil {
	// 	middleWare(w,r)
	// 	return
	// }
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
	w.Header().Set("Cache-Control","no-cache, no-store, must-revalidate")
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
		  jwtCookie := &http.Cookie{
			Name:     "jwt",
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
	  }
	  http.SetCookie(w, jwtCookie)
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
	
	if permission == "user" {
		http.Redirect(w,r,"/home",http.StatusSeeOther)
	}

	stmt, err := model.DB.Prepare("SELECT username,name FROM people where permission='user'")
    if err != nil {
        panic(err)
    }
    defer stmt.Close()

    // Execute the SELECT statement and retrieve all records
    rows, err := stmt.Query()
    if err != nil {
        panic(err)
    }
    defer rows.Close()

		var users []model.People
		for rows.Next() {
			var user model.People
			err := rows.Scan(&user.Username, &user.Name)
			if err != nil {
					panic(err)
			}
			users = append(users, user)
	}

	var adminDetails model.AdminDetails

	// take admin name
	sqlStatement := `SELECT name FROM people WHERE username=$1`
	row := model.DB.QueryRow(sqlStatement, username)

	// Scan the row into variables
	err = row.Scan(&adminDetails.AdminName)

	if err != nil {
    if err == sql.ErrNoRows {
			http.Redirect(w,r,"/",http.StatusSeeOther)
			return
		} 
	}

	adminDetails.Users = users

	// this much is the code

	fmt.Println(users)
	model.Tpl.ExecuteTemplate(w,"adminhomepage.html",adminDetails)
	

}


// Delete User

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("code reached here")
	w.Header().Set("Cache-Control","no-cache, no-store, must-revalidate")
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
		  jwtCookie := &http.Cookie{
			Name:     "jwt",
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
	  }
	  http.SetCookie(w, jwtCookie)
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
	
	if permission == "user" {
		http.Redirect(w,r,"/home",http.StatusSeeOther)
	}
	
	username = r.URL.Query().Get("username")
	_, err = model.DB.Exec("DELETE FROM people WHERE username=$1", username)
    if err != nil {
        panic(err)
    }

	http.Redirect(w,r,"/adminpanel",http.StatusSeeOther)

}




// Add A new user by the admin

func AddUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("code reached here")
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

	http.Redirect(w,r,"adminpanel",http.StatusSeeOther)
}