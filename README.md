A simple JWT library using HMAC with optional NaCl encryption of claims meant to address critical vulnerabilities posted at https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries

Algorithms: HS256, HS384 and HS512 only

Claims: set exp using the convenience function ExpiresInSeconds, ExpiresInMinutes or ExpiresInHours

Optional encryption of claims: call GenerateKey()

Generate a Token
----------------

```go
func Sign(alg string, claims map[string]interface{}, secret, naclKey string) (string, error)
```

Rules: 

- alg can be HS256, HS384 or HS512 only (none is an error)
- claims is a map or the equivalent of object in JavaScript
- secret is used in HMAC signing
- naclKey is used if you want to encrypt the claims (otherwise set it to "")
- call GenerateKey() to generate naclKey

Verify a Token
--------------

```go
func Verify(token, secret, naclKey string) (map[string]interface{}, error)
```

Returns the corresponding claims as map[string]interface{} if token is valid


Example
-------

```go
package main

import (
	"fmt"
	"github.com/ibmendoza/jwt"
	"time"
)

func main() {

	claims := make(map[string]interface{})
	claims["sub"] = "1234567890"
	claims["name"] = "John Doe"
	claims["admin"] = true
	claims["exp"] = jwt.ExpiresInSeconds(3)
	//claims["exp"] = jwt.ExpiresInMinutes(1)
	//claims["exp"] = jwt.ExpiresInHours(1)

	//fmt.Println(timeNow())

	naclKey, err := jwt.GenerateKey()
	fmt.Println(naclKey)

	token, err := jwt.Sign("HS384", claims, "secret", naclKey)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(token, err) //encrypted claims

	token2, err := jwt.Sign("HS256", claims, "secret", "")
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(token2, err) //non-encrypted claims

	timer1 := time.NewTimer(time.Second * 2)
	<-timer1.C

	//fmt.Println(timeNow()) //after 2sec

	fmt.Println(jwt.Verify(token, "secret", naclKey)) //true
	fmt.Println(jwt.Verify(token, "scret", ""))       //false

	fmt.Println(jwt.Verify(token2, "secret", ""))     //true
	fmt.Println(jwt.Verify(token2, "scret", ""))      //false
	fmt.Println(jwt.Verify(token2, "secret", "asdf")) //false
	fmt.Println(jwt.Verify(token2, "secret", ""))     //false

	timer1 = time.NewTimer(time.Second * 2) //after 4secs
	<-timer1.C

	fmt.Println(jwt.Verify(token, "secret", naclKey)) //expired
}
```

Author
-----

Isagani Mendoza (http://itjumpstart.wordpress.com)

License
-------

MIT

Always-Encrypted Token? Try Salt
--------------------------------

http://github.com/ibmendoza/salt


