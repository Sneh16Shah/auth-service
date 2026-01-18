package model

import "time"

// User model
type User struct {
	User_ID    int64     `json:"user_id"`
	Email      string    `json:"email"`
	Password   string    `json:"-"`
	First_Name string    `json:"first_name"`
	Last_Name  string    `json:"last_name"`
	Created_At time.Time `json:"created_at"`
	Updated_At time.Time `json:"updated_at"`
}

func NewUser(email, password, first_name, last_name string) *User {
	return &User{
		Email:      email,
		Password:   password,
		First_Name: first_name,
		Last_Name:  last_name,
	}
}
