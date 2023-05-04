package middleware

import (
	"log"
	"net/http"
	"time"

	"example.com/jwt-demo/model"
	"github.com/golang-jwt/jwt"
)



func CookieCreation(w http.ResponseWriter,username string) {
	token := jwt.New(jwt.SigningMethodHS256)
  claims := token.Claims.(jwt.MapClaims)
  claims["username"] = username
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
}

func AdminAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  
		tokenString, err := r.Cookie("jwt")
		if err != nil {
			http.Redirect(w,r,"/",http.StatusSeeOther)
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
			http.Redirect(w,r,"/",http.StatusSeeOther)
			return
		}
	
		// Extract the user's identity from the token.
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			http.Redirect(w,r,"/",http.StatusSeeOther)
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
			next.ServeHTTP(w,r)
			return
		}
	
		next.ServeHTTP(w,r)
			
		})
}


func Auth(next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  
  tokenString, err := r.Cookie("jwt")
	if err != nil {
		next.ServeHTTP(w,r)
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
		next.ServeHTTP(w,r)
		return
	}

	// Extract the user's identity from the token.
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		next.ServeHTTP(w,r)
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

  next.ServeHTTP(w,r)
    
  })
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