package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

var rsaKey *rsa.PrivateKey

func init() {
	var err error
	rsaKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
}

func encodeToBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func bigIntToBytes(i *big.Int) []byte {
	return i.Bytes()
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	keys := []JWK{}

	// Check if the RSA key is not nil
	if rsaKey != nil {
		key := JWK{
			Kty: "RSA",
			Kid: "your-key-identifier",
			Use: "sig",
			Alg: "RS256", // Replace with the appropriate algorithm
			N:   encodeToBase64URL(rsaKey.N.Bytes()),
			E:   encodeToBase64URL(bigIntToBytes(big.NewInt(int64(rsaKey.E)))),
		}
		keys = append(keys, key)
	}

	jwksResponse := JWKSResponse{
		Keys: keys,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(jwksResponse); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

func main() {
	r := mux.NewRouter()
	// Define your routes
	r.HandleFunc("/jwks", jwksHandler).Methods("GET")
	r.HandleFunc("/auth", authHandler).Methods("POST")

	// Register your routes with the router
	http.Handle("/", r)

	fmt.Println("Server is running on :8080...")
	http.ListenAndServe(":8080", nil)
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	expired := r.URL.Query().Get("expired")

	var token *jwt.Token
	if expired != "" {
		// If the "expired" query parameter is present, issue a JWT with an expired key
		token = generateKey("expired-key", time.Now().Add(-1*time.Hour))
	} else {
		// Issue a JWT with the current valid key
		token = generateKey("valid-key", time.Now().Add(24*time.Hour))
	}

	tokenString, err := token.SignedString(rsaKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(tokenString))
}

func generateKey(kid string, expiry time.Time) *jwt.Token {
	claims := jwt.MapClaims{
		"kid": kid,
		"exp": expiry.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token
}

