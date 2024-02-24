package routes

import (
	"github.com/gin-gonic/gin"
	"jwtokens/src/controllers"
)

func TokensRoutes(router *gin.Engine) {
	router.GET("/token/get", controllers.GetTokens())
	router.GET("/token/refresh", controllers.RefreshTokens())
}