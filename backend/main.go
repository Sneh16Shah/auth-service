package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"time"

	dbpkg "auth-service/db"
	"auth-service/model"
	"auth-service/utils"

	"golang.org/x/crypto/bcrypt"
)

type registerRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type apiResponse struct {
	Message      string `json:"message"`
	Token        string `json:"token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type refreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func writeJSON(w http.ResponseWriter, status int, payload apiResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeCORSHeaders(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	allowed := strings.TrimSpace(os.Getenv("CORS_ALLOW_ORIGINS"))
	if allowed == "" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		for _, o := range strings.Split(allowed, ",") {
			if strings.TrimSpace(o) == origin {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				break
			}
		}
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

func enforceMethods(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return false
	}
	for _, m := range allowed {
		if r.Method == m {
			return true
		}
	}
	if len(allowed) == 1 {
		w.Header().Set("Allow", allowed[0])
	} else if len(allowed) > 1 {
		w.Header().Set("Allow", strings.Join(allowed, ", "))
	}
	if r.Method == http.MethodGet || r.Method == http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Message: "Method not allowed"})
		return false
	}
	writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Message: "Method not allowed"})
	return false
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func validateEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	writeCORSHeaders(w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Message: "Method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Message: "Healthy"})
}

func serverHandler(w http.ResponseWriter, r *http.Request) {
	writeCORSHeaders(w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Message: "Method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Message: "Hello welcome to my server!"})
}

func registerHandler(w http.ResponseWriter, r *http.Request, db *dbpkg.DB) {
	writeCORSHeaders(w, r)
	if !enforceMethods(w, r, http.MethodPost) {
		return
	}

	var req registerRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Message: "Invalid request payload"})
		return
	}

	req.Email = normalizeEmail(req.Email)
	if req.Email == "" || !validateEmail(req.Email) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Message: "Invalid email"})
		return
	}

	if len(req.Password) < 8 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Message: "Password must be at least 8 characters"})
		return
	}
	if len(req.Password) > 72 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Message: "Password too long"})
		return
	}

	req.FirstName = strings.TrimSpace(req.FirstName)
	req.LastName = strings.TrimSpace(req.LastName)

	// validate if user already exist or not
	userExist, err := db.GetUser(req.Email)
	if err != nil {
		log.Println("GetUser error:", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Message: "Error checking user existence"})
		return
	}
	if userExist != nil {
		writeJSON(w, http.StatusConflict, apiResponse{Message: "User already exist"})
		return
	}

	if req.FirstName == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Message: "First name is required"})
		return
	}

	if req.LastName == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Message: "Last name is required"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Message: "Error creating user"})
		return
	}

	newUser := model.NewUser(req.Email, string(hashedPassword), req.FirstName, req.LastName)

	err = db.AddUser(newUser)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Message: "Error adding user to database"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Message: "Registered Successfully"})
}

func loginHandler(w http.ResponseWriter, r *http.Request, db *dbpkg.DB) {
	writeCORSHeaders(w, r)
	if !enforceMethods(w, r, http.MethodPost) {
		return
	}

	var req loginRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Message: "Invalid request payload"})
		return
	}

	req.Email = normalizeEmail(req.Email)
	if req.Email == "" || !validateEmail(req.Email) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Message: "Invalid email"})
		return
	}
	if req.Password == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Message: "Password is required"})
		return
	}

	// get user from db
	user, err := db.GetUser(req.Email)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Message: "Invalid email or password"})
		return
	}
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Message: "Invalid email or password"})
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Message: "Invalid email or password"})
		return
	}

	token, refreshToken, err := utils.GetTokenizer(uint(user.User_ID), user.Email)
	if err != nil {
		log.Println("Error generating token:", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Message: "Error generating token"})
		return
	}

	// store refresh token in db
	hashRefreshToken := hashToken(refreshToken)
	refreshTokenModel := model.NewRefreshToken(hashRefreshToken, user.User_ID, time.Now().Add(utils.RefreshTokenTTL()))
	err = db.AddRefreshToken(refreshTokenModel)
	if err != nil {
		log.Println("Error adding refresh token to database:", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Message: "Error adding refresh token"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Message: "Logged in", Token: token, RefreshToken: refreshToken})
}

func checkValidToken(w http.ResponseWriter, r *http.Request) {
	writeCORSHeaders(w, r)
	if !enforceMethods(w, r, http.MethodGet, http.MethodPost) {
		return
	}

	//validate header existis
	if _, ok := r.Header["Authorization"]; !ok {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Message: "Missing token"})
		return
	}

	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Message: "Missing token"})
		return
	}

	if !strings.HasPrefix(tokenString, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Message: "Invalid token format"})
		return
	}

	tokenString = tokenString[7:]
	if tokenString == "" {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Message: "Invalid token format"})
		return
	}

	err := utils.ValidateToken(tokenString)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Message: "Invalid token"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Message: "Valid token"})
}

func refreshTokenHandler(w http.ResponseWriter, r *http.Request, db *dbpkg.DB) {
	writeCORSHeaders(w, r)
	if !enforceMethods(w, r, http.MethodPost) {
		return
	}

	var req refreshTokenRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Message: "Invalid request payload"})
		return
	}

	if req.RefreshToken == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Message: "Refresh token is required"})
		return
	}

	// check refresh token in db
	hashRefreshToken := hashToken(req.RefreshToken)
	refreshTokenModel, err := db.GetRefreshToken(hashRefreshToken)
	if err != nil || refreshTokenModel == nil {
		writeJSON(w, http.StatusUnauthorized, apiResponse{Message: "Invalid refresh token"})
		return
	}

	// check refresh token expiration
	if refreshTokenModel.Expires_At.Before(time.Now()) {
		_ = db.RevokeRefreshToken(hashRefreshToken, nil)
		writeJSON(w, http.StatusUnauthorized, apiResponse{Message: "Refresh token expired"})
		return
	}
	if refreshTokenModel.Revoked_At != nil {
		_ = db.RevokeAllRefreshTokensForUser(refreshTokenModel.User_ID)
		writeJSON(w, http.StatusUnauthorized, apiResponse{Message: "Invalid refresh token"})
		return
	}

	// fetch the user
	user, err := db.GetUserByID(refreshTokenModel.User_ID)
	if err != nil || user == nil {
		log.Println("Error fetching user:", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Message: "Error fetching user"})
		return
	}

	// generate new tokens (rotation)
	token, newRefreshToken, err := utils.GetTokenizer(uint(user.User_ID), user.Email)
	if err != nil {
		log.Println("Error generating token:", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Message: "Error generating token"})
		return
	}

	newHashRefreshToken := hashToken(newRefreshToken)
	newRefreshTokenModel := model.NewRefreshToken(newHashRefreshToken, user.User_ID, time.Now().Add(utils.RefreshTokenTTL()))
	if err := db.AddRefreshToken(newRefreshTokenModel); err != nil {
		log.Println("Error adding refresh token to database:", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Message: "Error adding refresh token"})
		return
	}
	_ = db.RevokeRefreshToken(hashRefreshToken, &newHashRefreshToken)

	writeJSON(w, http.StatusOK, apiResponse{Message: "Token refreshed", Token: token, RefreshToken: newRefreshToken})
}

func logoutHandler(w http.ResponseWriter, r *http.Request, db *dbpkg.DB) {
	writeCORSHeaders(w, r)
	if !enforceMethods(w, r, http.MethodPost) {
		return
	}

	var req refreshTokenRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Message: "Invalid request payload"})
		return
	}

	if req.RefreshToken == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Message: "Refresh token is required"})
		return
	}

	hashRefreshToken := hashToken(req.RefreshToken)
	if err := db.RevokeRefreshToken(hashRefreshToken, nil); err != nil {
		log.Println("Error deleting refresh token from database:", err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{Message: "Error deleting refresh token"})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Message: "Logged out"})
}

func main() {
	log.Println("Starting auth-service...")
	http.HandleFunc("/", serverHandler)
	http.HandleFunc("/health", healthCheckHandler)

	db, err := dbpkg.NewDB()
	if err != nil {
		log.Println("Database connection error temporarily unavailable:", err)
	}
	if db != nil {
		err = db.InitDB()
		if err != nil {
			log.Println("Database initialization error:", err)
		}
	}

	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			writeCORSHeaders(w, r)
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			writeJSON(w, http.StatusInternalServerError, apiResponse{Message: "Database not available"})
			return
		}
		registerHandler(w, r, db)
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			writeCORSHeaders(w, r)
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			writeJSON(w, http.StatusInternalServerError, apiResponse{Message: "Database not available"})
			return
		}
		loginHandler(w, r, db)
	})

	//auth middleware
	http.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		checkValidToken(w, r)
	})

	//refresh token endpoint
	http.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			writeCORSHeaders(w, r)
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			writeJSON(w, http.StatusInternalServerError, apiResponse{Message: "Database not available"})
			return
		}
		refreshTokenHandler(w, r, db)
	})

	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			writeCORSHeaders(w, r)
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			writeJSON(w, http.StatusInternalServerError, apiResponse{Message: "Database not available"})
			return
		}
		logoutHandler(w, r, db)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Println("Listening on port " + port + "...")

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           http.DefaultServeMux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Println("Error:", err)
	}
}
