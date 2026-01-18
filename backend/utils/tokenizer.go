package utils

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type MyCustomClaims struct {
	UserID uint   `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

const tokenIssuer = "auth-service"

func GetTokenizer(userID uint, email string) (string, error) {
	claims := MyCustomClaims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			Issuer:    tokenIssuer,
		},
	}
	token_secret := os.Getenv("TOKEN_SECRET")
	if token_secret == "" {
		return "", fmt.Errorf("TOKEN_SECRET not set")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(token_secret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func ValidateToken(tokenString string) error {
	claims := MyCustomClaims{}
	token_secret := os.Getenv("TOKEN_SECRET")
	if token_secret == "" {
		return fmt.Errorf("TOKEN_SECRET not set")
	}
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method == nil || token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(token_secret), nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(tokenIssuer),
	)
	if err != nil || !token.Valid {
		return fmt.Errorf("invalid token: %v", err)
	}
	return nil
}
