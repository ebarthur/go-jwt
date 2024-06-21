package initializers

import "go-jwt/models"

func SyncDB() {
	DB.AutoMigrate(&models.User{})
}
