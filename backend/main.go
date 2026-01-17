package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"log"
	"os"

	dbpkg "auth-service/db"
	"auth-service/model"
	"auth-service/utils"

	"golang.org/x/crypto/bcrypt"
)

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Healthy"))
}

func serverHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello welcome to my server!"))
}

func registerHandler(w http.ResponseWriter, r *http.Request, db *dbpkg.DB) {
	// enable cors
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	var user *model.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid request payload"))
		return
	}
	// validate if user already exist or not
	userExist, err := db.GetUser(user.Email)
	if err != nil {
		fmt.Println("GetUser error:", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error checking user existence"))
		return
	}
	if userExist != nil {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte("User already exist"))
		return
	}

	if user.First_Name == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("First name is required"))
		return
	}

	if user.Last_Name == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Last name is required"))
		return
	}

	// add user to db
	newUser := model.NewUser(user.Email, user.Password, user.First_Name, user.Last_Name)

	err = db.AddUser(newUser)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error adding user to database"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Registered Successfully"))
}

func loginHandler(w http.ResponseWriter, r *http.Request, db *dbpkg.DB) {
	// enable cors
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	// get email, paswword
	var loginReq struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&loginReq)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid request payload"))
		return
	}

	// get user from db
	user, err := db.GetUser(loginReq.Email)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Invalid email or password"))
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginReq.Password)); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Invalid email or password"))
		return
	}

	token, err := utils.GetTokenizer(uint(user.User_ID), user.Email)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error generating token"))
		return
	}
	log.Println(token)

	// return user
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Logged in"))
}

func checkValidToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Missing token"))
		return
	}

	tokenString = tokenString[7:]

	err := utils.ValidateToken(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Invalid token"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Valid token"))
}

func main() {
	fmt.Println("Hello, World!")
	// listen to port 8080
	http.HandleFunc("/", serverHandler)
	http.HandleFunc("/health", healthCheckHandler)

	db, err := dbpkg.NewDB()
	if err != nil {
		fmt.Println("Database connection error temporarily unavailable:", err)
	}
	if db != nil {
		err = db.InitDB()
		if err != nil {
			fmt.Println("Database initialization error:", err)
		}
	}

	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Database not available"))
			return
		}
		registerHandler(w, r, db)
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Database not available"))
			return
		}
		loginHandler(w, r, db)
	})

	//auth middleware
	http.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		checkValidToken(w, r)
	})

	port := os.Getenv("PORT")
	fmt.Println("Listening on port " + port + "...")
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Println("Error:", err)
	}
}
