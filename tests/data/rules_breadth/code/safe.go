package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"

	"github.com/gin-contrib/cors"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/pbkdf2"
)

func run(s string, pw, key, salt, iv, secretKey []byte, keyFunc jwt.Keyfunc) {
	tok, _ := jwt.Parse(s, keyFunc, jwt.WithValidMethods([]string{"HS256"}))
	if tok.Method == jwt.SigningMethodNone {
		return
	}
	signed, _ := tok.SignedString(secretKey)
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCEncrypter(block, iv)
	dk := pbkdf2.Key(pw, salt, 4096, 32, sha256.New)
	c := cors.Config{
		AllowOriginFunc: func(origin string) bool { return origin == "https://app.corp.internal" },
	}
	d := cors.Config{AllowOrigins: []string{"https://app.corp.internal"}, AllowCredentials: true}
	_, _, _, _, _, _ = signed, cfg, mode, dk, c, d
}
