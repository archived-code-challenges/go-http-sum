package main

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

const (
	jwtExpirationTime = time.Hour
)

var (
	jwtKey        = []byte("my_secret_key")
	regexIntegers = regexp.MustCompile(`-?\d+`)
)

func sumNumericalContent(s string) (sum int, err error) {
	numbers := regexIntegers.FindAllString(s, -1)
	for i := range numbers {
		n, err := strconv.Atoi(numbers[i])
		if err != nil {
			return 0, fmt.Errorf("not recognized character, %q", numbers[i])
		}
		sum += n
	}
	return sum, err
}

// Create a struct that models the structure of a user, both in the request body, and in the DB
type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// usersDB is a list of known users
var usersDB = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

// authenticate can be used to check if a user exists in the in-memory "database"
func authenticate(username, password string) bool {
	expectedPassword, ok := usersDB[username]

	if !ok || expectedPassword != password {
		return false
	}

	return true
}

// signin returns a response containing a JWT (OAuth 2) token with the username as a subject.
// The response is a JSON payload build following the OAuth standard.
// Reference: https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/
func signin(w http.ResponseWriter, r *http.Request) {
	var creds Credentials

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// The username and the password don't have to be verified, but should not accept empty strings.
	if creds.Password == "" || creds.Username == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// the next lines can be uncommented to authorize users using an in-memory list of known users
	// if !authorize(creds.Username, creds.Password) {
	// 	w.WriteHeader(http.StatusUnauthorized)
	// 	return
	// }

	expirationTime := time.Now().Add(jwtExpirationTime)
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Declare the token with the algorithm used for signing, and the claims. Create the JWT token.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store") // ensure clients do not cache this request
	authResponse := struct {
		Token      string `json:"access_token"`
		Kind       string `json:"token_type"`
		Expiration int    `json:"expires_in"`
	}{
		tokenString,
		"Bearer",
		int(jwtExpirationTime.Seconds()),
	}

	b, err := json.Marshal(authResponse)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write(b)
}

// sum accepts an arbitrary JSON document as payload, finds all of the numbers throughout the
// document and adds them together.
func sum(w http.ResponseWriter, r *http.Request) {
	content, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sum, _ := sumNumericalContent(string(content))
	sumstring := strconv.Itoa(sum)

	hash := sha1.New()
	hash.Write([]byte(sumstring))
	sha16 := fmt.Sprintf("%x", hash.Sum(nil)) // convert result to base 16

	w.Write([]byte(sha16))
}

// authorize handler acts as a middleware that validates a JWT from the `Authorization` header.
func authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.Split(r.Header.Get("Authorization"), " ")
		if len(token) != 2 || strings.ToLower(token[0]) != "bearer" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		jwtToken, err := jwt.ParseWithClaims(token[1], &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err == jwt.ErrSignatureInvalid || !jwtToken.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// post handler acts as a middleware to exclude any method other than post.
func post(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func Router() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/auth", post(http.HandlerFunc(signin)))
	mux.Handle("/sum", post(authorize(http.HandlerFunc(sum))))

	return mux
}

func main() {
	log := log.New(os.Stdout, "go-http-sum : ", log.LstdFlags|log.Lmicroseconds|log.Lshortfile)

	server := http.Server{
		Addr:    ":8000",
		Handler: Router(),
	}

	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint

		// Handle an interrupt signal, shut down.
		if err := server.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout
			log.Printf("HTTP server Shutdown: %v", err)
		}
		close(idleConnsClosed)
	}()

	log.Printf("HTTP server started on: %q", server.Addr)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("HTTP server ListenAndServe: %v", err)
	}

	<-idleConnsClosed
}
