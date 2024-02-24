package models

type Token struct {
	UserId       string `bson:"uuid"`
	RefreshToken string `bson:"refreshToken"`
}
