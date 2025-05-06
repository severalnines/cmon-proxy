package jwt

import (
	"time"

	"github.com/golang-jwt/jwt"
)

func CreateToken(data map[string]interface{}, secret []byte, expiration time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"exp": time.Now().Add(expiration).Unix(),
	}
	for k, v := range data {
		claims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

func ValidateToken(tokenString string, secret []byte) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrSignatureInvalid
}
