package db

import (
	"auth-service/model"
	"database/sql"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type DB struct {
	*sql.DB
}

func NewDB() (*DB, error) {
	connStr := "host=db port=5432 user=postgres password=postgres dbname=postgres sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		db.Close()
		return nil, err
	}
	return &DB{db}, nil
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
	//hashing/encrypting password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(hashedPassword)

	query := `
	INSERT INTO users (user_id, email, password, first_name, last_name, created_at, updated_at)
	VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err = db.Exec(query, user.User_ID, user.Email, user.Password, user.First_Name, user.Last_Name, user.Created_At, user.Updated_At)
	if err != nil {
		return err
	}
	return nil
}

func (db *DB) UpdateUser(user *model.User) error {
	query := `
	UPDATE users
	SET email = $1, password = $2, first_name = $3, last_name = $4, updated_at = $5
	WHERE user_id = $6
	`
	_, err := db.Exec(query, user.Email, user.Password, user.First_Name, user.Last_Name, user.Updated_At, user.User_ID)
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
