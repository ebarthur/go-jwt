package controllers

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go-jwt/initializers"
	"go-jwt/models"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"os"
	"time"
)

type SignupRequestBody struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

func SignUp(c *gin.Context) {
	// get the email/pass from req body
	var body SignupRequestBody

	err := c.ShouldBindJSON(&body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})

		return
	}

	// create the user
	user := models.User{Email: body.Email, Password: string(hash)}

	result := initializers.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to create user"})

		return
	}

	// return response
	c.JSON(http.StatusCreated, gin.H{})
}

type LoginRequestBody struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

func Login(c *gin.Context) {
	// get the email/pass from req body
	var body LoginRequestBody

	err := c.ShouldBindJSON(&body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// look up requested user
	var user models.User
	initializers.DB.First(&user, "email = ?", body.Email)
	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email or password"})
		return
	}

	// compare sent in pass with saved user pass hash
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email or password"})
		return
	}

	// generate a jwt token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"subject": user.ID,
		"expiry":  time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create token"})
		return
	}

	// set cookies because why not? cookies are better
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{})
}

func Validate(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	// return message
	c.JSON(http.StatusOK, gin.H{
		"message":  "you're logged in",
		"userInfo": user, // for debugging purposesS
	})
}

type ChangePasswordRequestBody struct {
	Password string `json:"password" binding:"required"`
	NewPass  string `json:"new_pass" binding:"required,min=8"`
}

func ChangePassword(c *gin.Context) {
	// get current and new pass off body
	var body *ChangePasswordRequestBody

	err := c.Bind(&body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read body"})
		return
	}

	// get user from context(cookie)
	userInterface, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	user := userInterface.(models.User)

	// fetch user record from the database
	var dbUser models.User
	initializers.DB.First(&dbUser, "id=?", user.ID)
	if dbUser.ID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	// Check if new password matches the current password
	err = bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(body.NewPass))
	if err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "New password cannot match current one"})
		return
	}

	// compare current password with the stored password
	err = bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(body.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect current password"})
		return
	}

	// hash the new password
	newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(body.NewPass), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash new password"})
		return
	}

	// update the password in the database
	initializers.DB.Model(&dbUser).Update("Password", string(newHashedPassword))

	// return success
	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}
