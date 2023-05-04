package controller

import (
	// "database/sql"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"regexp"

	"time"

	"example.com/jwt-demo/middleware"
	"example.com/jwt-demo/model"
	"github.com/golang-jwt/jwt"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var errValue model.ErrorDetails


// login GET HANDLER
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control","no-cache, no-store, must-revalidate")
	// Create a new template with the name "home"
	//  _, err := r.Cookie("jwt")
	// if err == nil {
	// 	middleWare(w,r)
	// 	return
	// }

	// Execute the template with the PageData struct as input
	err := model.Tpl.ExecuteTemplate(w,"loginget.html",errValue)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	errValue.CommonError = ""


}

// signUP GET to allow user to enter details
func SignupHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control","no-cache, no-store, must-revalidate")
	// _, err := r.Cookie("jwt")
	// if err == nil {
	// 	middleWare(w,r)
	// 	return
	// }
	err := model.Tpl.ExecuteTemplate(w,"signupget.html", errValue )
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	errValue.EmailError = ""
	errValue.PasswordError = ""
}

//  To check where to redirect based on user and admin

func middleWare(w http.ResponseWriter, r *http.Request) {
	tokenString, err := r.Cookie("jwt")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Verify the token's signature.
	token, err := jwt.Parse(tokenString.Value, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret-key"), nil 
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

// 
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control","no-cache, no-store, must-revalidate")

	errValue.CommonError = ""
	errValue.EmailError = ""
	errValue.PasswordError = ""
	errValue.NameError = ""

	tokenString, err := r.Cookie("jwt")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Verify the token's signature.
	token, err := jwt.Parse(tokenString.Value, func(token *jwt.Token) (interface{}, error) {

		if _,ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("there was an error in parsing")
		}
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

	var userDetails model.UserDetails

	// take admin name
	sqlStatement := `SELECT name FROM people WHERE username=$1`
	row := model.DB.QueryRow(sqlStatement, username)

	// Scan the row into variables
	err = row.Scan(&userDetails.Name)

	if err != nil {
    if err == sql.ErrNoRows {
			http.Redirect(w,r,"/",http.StatusSeeOther)
			return
		} 
	}

	model.Tpl.ExecuteTemplate(w,"userhomepage.html",userDetails.Name)

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
			errValue.EmailError = "user does not exist, signup"
			http.Redirect(w,r,"/",http.StatusSeeOther)
			return
		} 
	}

	if username != user.Username {
		errValue.EmailError = "email incorrect"
		http.Redirect(w,r,"/",http.StatusSeeOther)
		return
	}

	byteHash := []byte(password)
    err = bcrypt.CompareHashAndPassword(byteHash, []byte(user.Password))
    if err != nil {
        errValue.PasswordError = "password incorrect"
    }

	// ########
	middleware.CookieCreation(w,user.Username)
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
			CPassword: r.FormValue("cpassword"),
			Permission: "user",
	}

	sqlStatement := `SELECT username FROM people WHERE username=$1`
	row := model.DB.QueryRow(sqlStatement, user.Username)

	// Scan the row into variables
	var username string
	err = row.Scan(&username)

	if err == nil {
    errValue.EmailError = "Email already exists" 
		http.Redirect(w,r,"/signup",http.StatusSeeOther)
		return
	}

		pattern := `^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`
    regex := regexp.MustCompile(pattern)
    if !regex.MatchString(user.Username) {
			errValue.EmailError = "Email not in the correct format"
			http.Redirect(w,r,"/signup",http.StatusSeeOther)
			return
		}


	if user.Password != user.CPassword {
		errValue.PasswordError = "password does not match"
		http.Redirect(w,r,"/signup",http.StatusSeeOther)
		return
	}

	// encrypting password
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.MinCost)
    if err != nil {
        log.Println(err)
    }
	user.Password = string(hash)

	// end of that checking 

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

	middleware.CookieCreation(w,user.Username)
	
	http.Redirect(w,r,"/home",http.StatusSeeOther)
	// w.WriteHeader(http.StatusCreated)


}



func AdminPanel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control","no-cache, no-store, must-revalidate")
	errValue.CommonError = ""
	errValue.EmailError = ""
	errValue.PasswordError = ""
	errValue.NameError = ""
	tokenString, err := r.Cookie("jwt")
	// if err != nil {
	// 	http.Redirect(w, r, "/", http.StatusSeeOther)
	// 	return
	// }

	// // Verify the token's signature.
	token, err := jwt.Parse(tokenString.Value, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret-key"), nil // Replace with your own secret key
	})
	
	// // Extract the user's identity from the token.
	claims, _ := token.Claims.(jwt.MapClaims)
	// if !ok || !token.Valid {
	// 	http.Redirect(w, r, "/", http.StatusSeeOther)
	// 	return
	// }
	username := claims["username"].(string)

	// // Check if the user is authorized to access the home page.
	// permission := isAuthorized(w,username)
	
	// if permission == "user" {
	// 	http.Redirect(w,r,"/home",http.StatusSeeOther)
	// }

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
	fmt.Println("code reached here 10")
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
	fmt.Println("code reached here 1")
	err := r.ParseForm()
	if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
	}
	var permission string
	if r.FormValue("checkbox") == "on" {
		permission = "admin" 
	} else {
		permission = "user"
	}

	// Create new user from form data
	user := model.People{
			Name:  r.FormValue("name"),
			Username : r.FormValue("username"),
			Password : r.FormValue("password"),
			Permission: permission,
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.MinCost)
    if err != nil {
        log.Println(err)
    }
	user.Password = string(hash)


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

// update user page GET REQUEST
func UpdateUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control","no-cache, no-store, must-revalidate")
	
	user := r.URL.Query().Get("username")
	name := r.URL.Query().Get("name")

	 userDetails :=  model.UserDetails {
			Username: user,
			Name: name,
	 }

	if user == "" {
		http.Redirect(w,r,"/adminpanel",http.StatusSeeOther)
		return
	}
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

	model.Tpl.ExecuteTemplate(w,"updatepage.html",userDetails)

}



//  update user POST REQUEST
func UpdateUserReal(w http.ResponseWriter, r *http.Request) {

	username := r.URL.Query().Get("username")
	err := r.ParseForm()
	if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
	}

	// Create new user from form data
	user := model.People{
			Name:  r.FormValue("name"),
	}
	fmt.Println("The code reached here")
	// Insert new user into database
	_, err = model.DB.Exec("UPDATE people SET name=$1 WHERE username=$2", user.Name, username)
	if err != nil {
		http.Error(w, fmt.Sprintf("Unable to update user: %v", err), http.StatusInternalServerError)
		return
	}

	http.Redirect(w,r,"/adminpanel",http.StatusSeeOther)
}


//  logging out user and admin
func Logout(w http.ResponseWriter, r *http.Request) {
	fmt.Println("The logout called")
	expired := time.Now().AddDate(0, 0, -1)
    cookie := http.Cookie{
        Name:     "jwt",
        Value:    "",
        Expires:  expired,
        Path:     "/",
        HttpOnly: true,
    }
    http.SetCookie(w, &cookie)
    http.Redirect(w, r, "/", http.StatusSeeOther)
}