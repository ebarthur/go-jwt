package types

type SignupRequestBody struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type LoginRequestBody struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type ChangePasswordRequestBody struct {
	Password string `json:"password" binding:"required"`
	NewPass  string `json:"new_pass" binding:"required,min=8"`
}
