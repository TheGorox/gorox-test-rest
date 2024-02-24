package controllers

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"crypto/sha512"
	"encoding/hex"
	"encoding/base64"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"

	db "jwtokens/src/database"
	"jwtokens/src/models"
)

var dotenvLoaded bool

func loadDotenv() {
	err := godotenv.Load(".env")
	if err != nil {
		panic(err)
	}

	dotenvLoaded = true
}

// var usersCollection *mongo.Collection = db.DBClient.Database("task").Collection("users")
var tokensCollection *mongo.Collection = db.DBClient.Database("task").Collection("tokens")

// todo: добавить индекс на поле uuid в таблицу tokens
func generateTokens(uuid string) (accessToken string, refreshToken string) {
	accessToken = generateAccessToken(uuid)
	refreshToken = generateRefreshToken(accessToken)

	// немного некрасиво, но будем добавлять токен в БД здесь
	var tokenObj models.Token
	tokenObj.UserId = uuid

	refreshTokenCrypted, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	tokenObj.RefreshToken = string(refreshTokenCrypted)

	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	_, err = tokensCollection.InsertOne(ctx, tokenObj)
	if err != nil {
		panic(err)
	}

	return accessToken, refreshToken
}

type TokenClaims struct {
	Uuid    string    `json:"uuid"`
	Expires time.Time `json:"expires"`
	jwt.StandardClaims
}

func generateAccessToken(uuid string) string {
	claims := &TokenClaims{
		Uuid:           uuid,
		Expires:        time.Now().Add(24 * time.Hour),
		StandardClaims: jwt.StandardClaims{},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	accessTokenString, err := accessToken.SignedString([]byte(os.Getenv("JWT_SECRET")))

	if err != nil {
		panic(err)
	}

	return accessTokenString
}

func generateRefreshToken(accessToken string) string {
	// создаём refreshToken на основе accessToken(доказательство связности) и секретного ключа
	hash := sha512.New512_256()

	hash.Write([]byte(accessToken))
	hash.Write([]byte(os.Getenv("JWT_SECRET")))

	hashBytes := hash.Sum(nil)
	refreshToken := hex.EncodeToString(hashBytes)

	

	return refreshToken
}

// не только валидирует, но и возвращает claims
func validateAccessToken(tokenString string, checkExpiry bool) (isValid bool, tokenClaims *TokenClaims) {
	if !dotenvLoaded {
		loadDotenv()
	}

	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{},
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("error in signing method")
			}

			return []byte(os.Getenv("JWT_SECRET")), nil
		})

	if err != nil {
		fmt.Println(err)
		return false, nil
	}

	if !token.Valid {
		return false, nil
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return false, nil
	}

	// не проверяем Expiry, например, если нужно сделать refresh
	if checkExpiry {
		expires := claims.Expires
		if time.Now().After(expires) {
			return false, nil
		}

		return true, claims
	}

	return true, claims
}

func validateRefreshTokenHash(accessToken string, refreshToken string) (isValid bool) {
	// refreshToken получается из комбинации accessToken+JWT_SECRET
	// так мы и сможем проверить их на связанность

	hash := sha512.New512_256()

	hash.Write([]byte(accessToken))
	hash.Write([]byte(os.Getenv("JWT_SECRET")))

	hashBytes := hash.Sum(nil)
	refreshTokenShouldBe := hex.EncodeToString(hashBytes)

	return refreshToken == refreshTokenShouldBe
}

// NOTE при валидации если токен есть в базе, то он удаляется
func validateRefreshTokenDB(refreshToken string, uuid string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	findResultCursor, findErr := tokensCollection.Find(ctx, bson.M{
		"uuid": uuid,
	})

	if findErr != nil {
		panic(findErr)
	}

	defer findResultCursor.Close(ctx)

	found := false

	// что делать, придётся итерировать по всем токенам
	for findResultCursor.Next(ctx) {
		var token models.Token
		if err := findResultCursor.Decode(&token); err != nil {
			continue
		}

		err := bcrypt.CompareHashAndPassword([]byte(token.RefreshToken), []byte(refreshToken))
		if err == nil {
			found = true
			// избавляемся от использованного токена
			_, _ = tokensCollection.DeleteOne(ctx, token)
			break
		}
	}

	if !found {
		// подлец, решил использовать токен ещё раз
		// логгим чтобы в случае брутфорса вычислить недоброжелателя
		log.Printf("[id=%s] использовал refresh токен повторно", uuid)
		return false
	}

	return true
}

func GetTokens() gin.HandlerFunc {
	return func(c *gin.Context) {
		// в данном случае, проверка через бд не требуется
		// т.к. можно подсунуть что угодно...
		uuid := c.Query("uuid")

		accessToken, refreshToken := generateTokens(uuid)

		// кодирую в base64 только при передаче потому, что при изначальном
		// кодировании в base64 токен по какой-то причине не всегда проходит валидацию
		refreshTokenEncoded := base64.StdEncoding.EncodeToString([]byte(refreshToken))

		// accessToken хранится в cookie,
		// refreshToken хранится в localStorage через js

		// 86400 - сутки
		// хотя, теряется смысл в отстуствии проверки Expires токена, если куки всё равно удалится из браузера...
		c.SetCookie("token", accessToken, 86400, "/", "localhost", false, false)

		c.JSON(200, gin.H{"refreshToken": refreshTokenEncoded})
	}
}

func RefreshTokens() gin.HandlerFunc {
	return func(c *gin.Context) {
		accessToken, notFoundErr := c.Cookie("token")
		if notFoundErr != nil {
			c.JSON(403, gin.H{"error": "not authorized"})
			return
		}

		refreshTokenEncoded := c.Query("refreshToken")
		if refreshTokenEncoded == "" {
			c.JSON(400, gin.H{"error": "refreshToken is not present"})
			return
		}

		
		refreshTokenBytes, decodeErr := base64.StdEncoding.DecodeString(refreshTokenEncoded)
		if decodeErr != nil {
			c.JSON(400, gin.H{"error": "refreshToken is invalid"})
			return
		}
		refreshToken := string(refreshTokenBytes)

		// сначала валидируем хеш токена, т.к. это быстрее
		valid := validateRefreshTokenHash(accessToken, refreshToken)
		if !valid {
			c.JSON(400, gin.H{"error": "refreshToken is invalid"})
			return
		}

		// fixme отключить валидацию вовсе и только лишь парсить токен или не стоит?
		_, tokenClaimsPtr := validateAccessToken(accessToken, false)

		uuid := (*tokenClaimsPtr).Uuid

		valid = validateRefreshTokenDB(refreshToken, uuid)
		if !valid {
			c.JSON(400, gin.H{"error": "refreshToken is already used"})
			return
		}

		// все условия пройдены, можем наконец выдать новые токены (от старого refresh избавились в validateRefreshTokenDB)
		newAccessToken, newRefreshToken := generateTokens(uuid)
		// новый токен уже сохранён в бд, осталось его выдать и дело с концом

		c.SetCookie("token", newAccessToken, 86400, "/", "localhost", false, false)

		c.JSON(200, gin.H{"refreshToken": newRefreshToken})
	}
}
