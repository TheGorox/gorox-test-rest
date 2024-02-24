package database

import (
	"context"
	"os"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// основа взята из официальной документации
func getDBClient() *mongo.Client {
	err := godotenv.Load(".env")
	if err != nil {
		panic("Failed to load .env file!")
	}

	url := os.Getenv("MONGO_URL")
	
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI(url).SetServerAPIOptions(serverAPI)
	
	client, err := mongo.Connect(context.Background(), opts)
	if err != nil {
		panic(err)
	}

	return client
}

var DBClient = getDBClient()