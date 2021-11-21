package jwt

import "github.com/dgrijalva/jwt-go"

type Maker interface{
	CreateToken(payload interface{}) (string, error)
	VerifyToken(token string) (*jwt.Token, error)
}