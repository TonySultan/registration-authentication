package main

import (
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

type User struct {
	gorm.Model
	Username string `json:"username"`
	Password string `json:"-"`
}

var db *gorm.DB

func init() {
	var err error
	db, err = gorm.Open("postgres", "user=username dbname=mydb sslmode=disable password=mypassword")
	if err != nil {
		panic("Failed to connect to database")
	}
	db.AutoMigrate(&User{})
}

func main() {
	r := gin.Default()
	r.POST("/login", login)
	r.POST("/register", register)

	auth := r.Group("/auth")
	auth.Use(authMiddleware)
	auth.GET("/protected", protectedHandler)

	r.Run(":8080")
}

func login(ctx *gin.Context) {

}
func register(ctx *gin.Context) {

}

func authMiddleware(ctx *gin.Context) {

}

func protectedHandler(ctx *gin.Context) {

}
