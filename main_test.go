package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt"
)

func Test_sumContent(t *testing.T) {
	tests := []struct {
		s       string
		wantSum int
	}{
		{s: `[-1,{"a":1, "b":"light"}]`, wantSum: 0},
		{s: `{"a":[-1,1,"dark"]}`, wantSum: 0},
		{s: `{"a":{"b":4},"c":-2}`, wantSum: 2},
		{s: `[[[2]]]`, wantSum: 2},
		{s: "[1,2,3,4]", wantSum: 10},
		{s: `{"a":6,"b":4}`, wantSum: 10},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			gotSum, err := sumNumericalContent(tt.s)
			if err != nil {
				t.Errorf("sumContent() error = %v", err)
				return
			}
			if gotSum != tt.wantSum {
				t.Errorf("sumContent() = %v, want %v", gotSum, tt.wantSum)
			}
		})
	}
}

func Test_authorize(t *testing.T) {
	t.Run("test JWT auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", http.NoBody)

		// Create a token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{StandardClaims: jwt.StandardClaims{}})
		tokenString, err := token.SignedString([]byte("my_test_secret_key"))
		if err != nil {
			t.Error(err)
			return
		}
		req.Header.Add("Authorization", "Bearer "+tokenString)

		// Hard-code global jwtKey to ensure authorization against test key
		jwtKey = []byte("my_test_secret_key")

		rr := httptest.NewRecorder()
		f := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
		handler := authorize(f)
		handler.ServeHTTP(rr, req)

		resultStatusCode := rr.Result().StatusCode
		if http.StatusOK != resultStatusCode {
			t.Errorf("authorize() = unexpected response code: %d", resultStatusCode)
		}
	})
}

func Test_authorizeError(t *testing.T) {
	t.Run("test JWT auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", http.NoBody)

		// Create a token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{StandardClaims: jwt.StandardClaims{}})
		tokenString, err := token.SignedString([]byte("my_test_secret_key"))
		if err != nil {
			t.Error(err)
			return
		}
		req.Header.Add("Authorization", "Bearer "+tokenString)

		// Hard-code global jwtKey to force error on authorization
		jwtKey = []byte("wrong_secret_key")

		rr := httptest.NewRecorder()
		f := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
		handler := authorize(f)
		handler.ServeHTTP(rr, req)

		resultStatusCode := rr.Result().StatusCode
		if http.StatusUnauthorized != resultStatusCode {
			t.Errorf("authorize() = unexpected response code: %d", resultStatusCode)
		}
	})
}

func Test_sum(t *testing.T) {
	t.Run("test sum", func(t *testing.T) {
		body := `[1,2,3,4]`
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
		rr := httptest.NewRecorder()

		sum(rr, req)

		b, _ := io.ReadAll(rr.Body)
		bodyResponse := string(b)

		expectedHash := "b1d5781111d84f7b3fe45a0852e59758cd7a87e5"
		if string(b) != expectedHash {
			t.Errorf("sum() want=%s, got=%s", expectedHash, bodyResponse)
		}
	})
}

func Test_signin(t *testing.T) {
	t.Run("test signin", func(t *testing.T) {
		body := `{"username":"user1","password":"password1"}`
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
		rr := httptest.NewRecorder()

		signin(rr, req)

		var result struct {
			Token      string `json:"access_token"`
			Kind       string `json:"token_type"`
			Expiration int    `json:"expires_in"`
		}

		err := json.Unmarshal(rr.Body.Bytes(), &result)
		if err != nil {
			t.Errorf("signin() error trying to unmarshal body")
		}

		expectedExpiration := int(jwtExpirationTime.Seconds())
		if result.Expiration != expectedExpiration {
			t.Errorf("signin() unexpected expiration time, want=%d, got=%d", expectedExpiration, result.Expiration)
		}

		expectedKind := "Bearer"
		if result.Kind != expectedKind {
			t.Errorf("signin() unexpected token type want=%s, got=%s", result.Kind, expectedKind)
		}

		token, err := jwt.Parse(result.Token, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("signin() unexpected signing method: %v", token.Header["alg"])
			}
			return jwtKey, nil
		})

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if claims["username"] != "user1" {
				t.Errorf("signin() unexpected username: want=%d, got=%d", expectedExpiration, result.Expiration)
			}

			expirationTime, ok := claims["exp"].(float64)
			if !ok {
				t.Errorf("signin() expected expiration time: want=%d, got=nil", expectedExpiration)
			}
			if expirationTime < 0 {
				t.Errorf("signin() unexpected username: want=%d, got=%d", expectedExpiration, result.Expiration)
			}
		}
	})
}
