package main

import (
    "os"

    routes "jwtokens/src/routes"

    "github.com/gin-gonic/gin"
)

func main() {
	// dotenv файл уже должен быть загружен через getDBClient
    port := os.Getenv("PORT")

    if port == "" {
        port = "3000"
    }

    router := gin.New()
    router.Use(gin.Logger()) // классная штука
    routes.TokensRoutes(router)

    router.Run(":" + port)
}