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

type RefreshToken struct {
	Hash_Refresh_Token string     `json:"-"`
	User_ID            int64      `json:"user_id"`
	Expires_At         time.Time  `json:"expires_at"`
	Revoked_At         *time.Time `json:"revoked_at,omitempty"`
	Replaced_By_Hash   *string    `json:"replaced_by_hash,omitempty"`
	Created_At         time.Time  `json:"created_at"`
	Updated_At         time.Time  `json:"updated_at"`
}

func NewRefreshToken(hash_refresh_token string, user_id int64, expires_at time.Time) *RefreshToken {
	return &RefreshToken{
		Hash_Refresh_Token: hash_refresh_token,
		User_ID:            user_id,
		Expires_At:         expires_at,
	}
}
