package main

import (
	"github.com/gin-gonic/gin"
	"go-jwt/controllers"
	"go-jwt/initializers"
	"go-jwt/middleware"
	"net/http"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDB()
	initializers.SyncDB()
}

func SetUpRouter() *gin.Engine {
	r := gin.Default()

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "pong"})
	})
	r.GET("/validate", middleware.RequireAuth, controllers.Validate)
	r.POST("/x/sign-up", controllers.SignUp)
	r.POST("/x/sign-in", controllers.Login)
	r.POST("/x/reset-password", middleware.RequireAuth, controllers.ChangePassword)

	return r
}

func main() {
	router := SetUpRouter()
	err := router.Run() // listen and serve on 0.0.0.0:3000

	if err != nil {
		panic(err)
	}
}

// $ compiledaemon --command="./go-jwt"
