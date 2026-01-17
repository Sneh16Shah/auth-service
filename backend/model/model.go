package model

import "time"

// User model
type User struct {
	User_ID int `json:"user_id"`
	Email string `json:"email"`
	Password string `json:"password"`
	First_Name string `json:"first_name"`
	Last_Name string `json:"last_name"`
	Created_At time.Time `json:"created_at"`
	Updated_At time.Time `json:"updated_at"`
}

func NewUser(email, password, first_name, last_name string) *User {
	// generate user_id
	User_ID := int(time.Now().UnixNano())
	return &User{
		User_ID: User_ID,
		Email: email,
		Password: password,
		First_Name: first_name,
		Last_Name: last_name,
		Created_At: time.Now(),
		Updated_At: time.Now(),
	}
}
