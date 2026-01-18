package db

import (
	"auth-service/model"
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "github.com/lib/pq"
)

type DB struct {
	*sql.DB
}

func getEnv(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}

func NewDB() (*DB, error) {
	host := getEnv("DB_HOST", "db")
	port := getEnv("DB_PORT", "5432")
	dbname := getEnv("DB_NAME", "postgres")
	password := getEnv("DB_PASSWORD", "postgres")
	user := getEnv("DB_USER", "postgres")

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)

	var lastErr error
	for i := 0; i < 10; i++ {
		conn, err := sql.Open("postgres", connStr)
		if err != nil {
			lastErr = err
		} else {
			err = conn.Ping()
			if err == nil {
				return &DB{conn}, nil
			}
			lastErr = err
			conn.Close()
		}
		time.Sleep(1 * time.Second)
	}
	return nil, lastErr
}

func (db *DB) InitDB() error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		user_id BIGSERIAL PRIMARY KEY,
		email VARCHAR(255) UNIQUE NOT NULL,
		password VARCHAR(255) NOT NULL,
		first_name VARCHAR(255) NOT NULL,
		last_name VARCHAR(255) NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err := db.Exec(query)
	if err != nil {
		return err
	}
	return nil
}

func (db *DB) AddUser(user *model.User) error {
	query := `
	INSERT INTO users (email, password, first_name, last_name)
	VALUES ($1, $2, $3, $4)
	RETURNING user_id, created_at, updated_at
	`
	err := db.QueryRow(query, user.Email, user.Password, user.First_Name, user.Last_Name).Scan(&user.User_ID, &user.Created_At, &user.Updated_At)
	if err != nil {
		return err
	}
	return nil
}

func (db *DB) UpdateUser(user *model.User) error {
	query := `
	UPDATE users
	SET email = $1, password = $2, first_name = $3, last_name = $4, updated_at = CURRENT_TIMESTAMP
	WHERE user_id = $5
	`
	_, err := db.Exec(query, user.Email, user.Password, user.First_Name, user.Last_Name, user.User_ID)
	if err != nil {
		return err
	}
	return nil
}

func (db *DB) GetUser(email string) (*model.User, error) {
	query := `
	SELECT user_id, email, password, first_name, last_name, created_at, updated_at
	FROM users
	WHERE email = $1
	`
	var user model.User
	err := db.QueryRow(query, email).Scan(&user.User_ID, &user.Email, &user.Password, &user.First_Name, &user.Last_Name, &user.Created_At, &user.Updated_At)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}
