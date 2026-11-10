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

func run(s string, pw, key []byte) {
	// expect-next: JWT003
	jwt.Parse(s, func(t *jwt.Token) (interface{}, error) { return jwt.UnsafeAllowNoneSignatureType, nil })
	// expect-next: JWT003
	unsigned := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"sub": "admin"})
	_ = unsigned
	// expect-next: JWT004
	tok, _, _ := jwt.NewParser().ParseUnverified(s, jwt.MapClaims{})
	// expect-next: JWT007
	signed, _ := tok.SignedString([]byte("hardcoded-secret"))
	// expect-next: TLS006
	cfg := &tls.Config{MinVersion: tls.VersionTLS10}
	block, _ := aes.NewCipher(key)
	// expect-next: CRY010
	mode := cipher.NewCBCEncrypter(block, []byte("0123456789abcdef"))
	// expect-next: CRY011
	dk := pbkdf2.Key(pw, []byte("fixedsalt"), 4096, 32, sha256.New)
	c := cors.Config{
		// expect-next: CORS002
		AllowOriginFunc: func(origin string) bool { return true },
	}
	// expect-next: CORS001
	d := cors.Config{AllowAllOrigins: true, AllowCredentials: true}
	_, _, _, _, _, _ = signed, cfg, mode, dk, c, d
}
