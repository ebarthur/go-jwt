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

func SignUp(c *gin.Context) {
	// get the email/pass from req body
	var body struct {
		Email    string
		Password string
	}

	err := c.Bind(&body)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})

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
	c.JSON(http.StatusOK, gin.H{})
}

func Login(c *gin.Context) {

	// get the email/pass from req body
	var body struct {
		Email    string
		Password string
	}

	err := c.Bind(&body)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})

		return
	}

	// look up requested user
	var user *models.User
	initializers.DB.First(&user, "email = ?", body.Email)

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid email or password"})

		return

	}

	// compare sent in pass with saved user pass hash
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid email or password"})

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
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to create token"})

		return
	}
	// send the token back
	//c.JSON(http.StatusOK, gin.H{
	//	"token": tokenString,
	//})

	// set cookies because why not? cookies are better
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{})
}

var user *models.User

func Validate(c *gin.Context) {
	user, _ := c.Get("user")
	c.JSON(http.StatusOK, gin.H{
		"message":  "you're logged in",
		"userInfo": user,
	})
}
