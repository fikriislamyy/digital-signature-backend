package main

import (
	"backend/controllers"
	"backend/initializers"
	"backend/middleware"

	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
	initializers.SyncDatabase()
}

func main() {
	r := gin.Default()
	r.POST("/signup", controllers.SignUp)
	r.POST("/login", controllers.Login)
	r.GET("/validate", middleware.RequireAuth, controllers.Validate)
	r.POST("/sign", middleware.RequireAuth, controllers.SignDocument)
	r.POST("/download/:id", middleware.RequireAuth, controllers.DownloadDocument)
	r.Run()
}
