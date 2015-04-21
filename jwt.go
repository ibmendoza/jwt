//Author: Isagani Mendoza (http://itjumpstart.wordpress.com)
//License: MIT

//This package addresses some flaws in JWT specifications
//https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries

//alg = none is an error
//exp is the only registered claim name that is being decoded
//uses HMAC algorithms only, no RSA
//secret can be a plain string
//the two functions (Sign and Verify) were based on jsonwebtoken by Auth0

package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/ibmendoza/cryptohelper"
	"hash"
	"log"
	"strings"
	"time"
)

const (
	HS256 = "HS256"
	HS384 = "HS384"
	HS512 = "HS512"
)

var errAlgorithm = errors.New("Algorithm must be HS256, HS384 or HS512")

/*
Header:
{
  "alg": "HS256",
  "typ": "JWT"
}

Claims:

{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}

http://jwt.io

var headers = base64URLencode(Header);
var claims = base64URLencode(Claims);
var payload = header + "." + claims;
var signature = base64URLencode(HMACSHA256(payload, secret));

var encodedJWT = payload + "." + signature;

*/

//generate NaCl key for use in Sign function
func GenerateKey() (string, error) {
	return cryptohelper.RandomKey()
}

func ExpiresInSeconds(d time.Duration) int64 {
	return time.Now().Add(time.Second * d).Unix()
}

func ExpiresInMinutes(d time.Duration) int64 {
	return time.Now().Add(time.Minute * d).Unix()
}

func ExpiresInHours(d time.Duration) int64 {
	return time.Now().Add(time.Hour * d).Unix()
}

func computeHmac(alg, message, secret string) string {
	key := []byte(secret)

	var h hash.Hash

	if alg == HS256 {
		h = hmac.New(sha256.New, key)
	}

	if alg == HS384 {
		h = hmac.New(sha512.New384, key)
	}

	if alg == HS512 {
		h = hmac.New(sha512.New, key)
	}

	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

//returns the corresponding claims as map[string]interface{} if token is valid
func Verify(token, secret, naclKey string) (map[string]interface{}, error) {

	//var payload = header + "." + claims;
	//var signature = base64URLencode(HMACSHA256(payload, secret));
	//var encodedJWT = payload + "." + signature;
	//token = header.claims.signature

	slcStr := strings.Split(token, ".")

	if len(slcStr) != 3 {
		return nil, errors.New("Invalid segment count in token")
	}

	header := slcStr[0]
	claims := slcStr[1]
	payload := header + "." + claims

	//extract algorithm in header
	jsonHeader, _ := base64.URLEncoding.DecodeString(header)

	mapHeader := make(map[string]string)
	byteHeader := []byte(jsonHeader)
	if err := json.Unmarshal(byteHeader, &mapHeader); err != nil {
		return nil, errors.New("Error in extracting algorithm in header")
	}

	alg := mapHeader["alg"]
	if !(alg == HS256 || alg == HS384 || alg == HS512) {
		return nil, errors.New("Invalid algorithm")
	}

	var err error
	var byteClaims []byte

	if naclKey != "" {

		claims, err = cryptohelper.SecretboxDecrypt(claims, naclKey)

		if err != nil {
			return nil, errors.New("Error decrypting claims")
		}
	} else {

		byteClaims, err = base64.URLEncoding.DecodeString(claims)
		if err != nil {
			return nil, errors.New("Error decoding claims")
		}
	}

	mapClaims := make(map[string]interface{})

	if naclKey == "" {
		if err := json.Unmarshal(byteClaims, &mapClaims); err != nil {
			return nil, err
		}
	}

	if naclKey != "" {
		if err := json.Unmarshal([]byte(claims), &mapClaims); err != nil {
			return nil, err
		}
	}

	//if exp is not set, expiry is 0 (meaning no expiry)
	expiry, ok := mapClaims["exp"].(float64)

	if ok {
		if float64(timeNow()) > expiry {
			return nil, errors.New("Token is expired")
		}
	}

	hmacPayloadSecret := computeHmac(alg, payload, secret)

	signature := base64.URLEncoding.EncodeToString([]byte(hmacPayloadSecret))

	isValidToken := token == payload+"."+signature

	if isValidToken {
		return mapClaims, nil
	} else {
		return nil, errors.New("Invalid token")
	}
}

//Sign generates a JWT
//alg can be HS256, HS384 or HS512 only (none is an error)
//claims is a map or the equivalent of object in JavaScript
//secret is used in HMAC signing
//naclKey is used if you want to encrypt the claims (otherwise set it to "")
//call GenerateKey() to generate naclKey
//https://auth0.com/blog/2014/01/27/ten-things-you-should-know-about-tokens-and-cookies/
func Sign(alg string, claims map[string]interface{}, secret, naclKey string) (string, error) {

	if !(alg == HS256 || alg == HS384 || alg == HS512) {
		log.Fatal(errAlgorithm)
	}

	header := map[string]string{"alg": alg, "typ": "JWT"}
	jsonHeader, _ := json.Marshal(header)

	byteClaims, err := json.Marshal(claims)

	if err != nil {
		return "", errors.New("Error in JSON marshal of claims")
	}

	var b64claims string

	if naclKey != "" {
		var err error
		b64claims, err = cryptohelper.SecretboxEncrypt(string(byteClaims), naclKey)

		if err != nil {
			return "", errors.New("Error encrypting claims")
		}
	} else {
		b64claims = base64.URLEncoding.EncodeToString(byteClaims)
	}

	b64header := base64.URLEncoding.EncodeToString(jsonHeader)

	payload := b64header + "." + b64claims

	hmacPayloadSecret := computeHmac(alg, payload, secret)

	signature := base64.URLEncoding.EncodeToString([]byte(hmacPayloadSecret))

	encodedJWT := payload + "." + signature

	return encodedJWT, nil
}

func timeNow() int64 {
	return time.Now().Unix()
}
