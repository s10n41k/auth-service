package model

type UserRefresh struct {
	SessionId string `json:"session_id"`
	UserID    string
	Name      string
	Email     string
	Role      string
	Version   int
}

type UserTemporary struct {
	SessionId string `json:"session_id"`
	Code      string
	Name      string
	Email     string
	Password  string
}
