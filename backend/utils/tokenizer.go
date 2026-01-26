package utils

import (
	"crypto/rand"
	"encoding/base64"
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

func durationFromEnv(key string, fallback time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return d
}

func AccessTokenTTL() time.Duration {
	return durationFromEnv("ACCESS_TOKEN_TTL", 5*time.Minute)
}

func RefreshTokenTTL() time.Duration {
	return durationFromEnv("REFRESH_TOKEN_TTL", 5*24*time.Hour)
}

func newOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func GetTokenizer(userID uint, email string) (string, string, error) {
	accessClaims := MyCustomClaims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenTTL())),
			Issuer:    tokenIssuer,
		},
	}
	token_secret := os.Getenv("TOKEN_SECRET")
	if token_secret == "" {
		return "", "", fmt.Errorf("TOKEN_SECRET not set")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	tokenString, err := token.SignedString([]byte(token_secret))
	if err != nil {
		return "", "", err
	}
	refreshTokenString, err := newOpaqueToken()
	if err != nil {
		return "", "", err
	}
	return tokenString, refreshTokenString, nil
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
