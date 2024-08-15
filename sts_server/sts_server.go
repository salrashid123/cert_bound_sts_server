package main

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"time"

	"net/http"

	"log"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"golang.org/x/net/http2"
)

type contextKey string

const contextEventKey contextKey = "event"
const contextCertificateHashKey contextKey = "certificateHash"

// https://www.rfc-editor.org/rfc/rfc8693.html#section-2.2.1
type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type,omitempty"`
	ExpiresIn       int64  `json:"expires_in,omitempty"`
	Scope           string `json:"scope,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
}

// support standard TokenTypes
const (
	AccessToken  string = "urn:ietf:params:oauth:token-type:access_token"
	RefreshToken string = "urn:ietf:params:oauth:token-type:refresh_token"
	IDToken      string = "urn:ietf:params:oauth:token-type:id_token"
	SAML1        string = "urn:ietf:params:oauth:token-type:saml1"
	SAML2        string = "urn:ietf:params:oauth:token-type:saml2"
	JWT          string = "urn:ietf:params:oauth:token-type:jwt"
)

type CNF struct {
	X5T string `json:"x5t#S256,omitempty"`
}

type CustomClaimsExample struct {
	*jwt.RegisteredClaims
	CNF `json:"cnf"`
}

const ()

var (
	port          = flag.String("port", ":8081", "port")
	tlsCert       = flag.String("tlsCert", "server.crt", "Server Certificate")
	tlsKey        = flag.String("tlsKey", "server.key", "Server Key")
	tlsCA         = flag.String("tlsCA", "tls-ca.crt", "Client Certificate CA")
	jwtPrivateKey = flag.String("jwtPrivateKey", "jwt.key", "Private Key to sign the JWT")
	jwtKeyID      = flag.String("jwtKeyID", "61c8b23ef9f935c0d98cf57bd4862c146e7b9fb7", "The keyid for the JWT")
	jwtIssuerCA   = flag.String("jwtIssuerCA", "tls-ca.crt", "Client Certificate CA")
	// support standard TokenTypes
	tokenTypes = []string{AccessToken, RefreshToken, IDToken, SAML1, SAML2, JWT}

	jwtKey *rsa.PrivateKey

	server *http.Server
)

type stsRequest struct {
	GrantType        string `json:"grant_type"`
	Resource         string `json:"resource,omitempty"`
	Audience         string `json:"audience,omitempty"`
	Scope            string `json:"scope,omitempty"`
	RequestTokenType string `json:"requested_token_type,omitempty"`
	SubjectToken     string `json:"subject_token"`
	SubjectTokenType string `json:"subject_token_type"`
	ActorToken       string `json:"actor_token,omitempty"`
	ActorTokenType   string `json:"actor_token_type,omitempty"`
}

func isValidTokenType(str string) bool {
	for _, a := range tokenTypes {
		if a == str {
			return true
		}
	}
	return false
}

func eventsMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ctx := r.Context()
		var clientCertificateHash string
		if len(r.TLS.PeerCertificates) > 0 {
			v := r.TLS.PeerCertificates[0]
			hasher := sha256.New()
			hasher.Write(v.Raw)
			clientCertificateHash = base64.StdEncoding.EncodeToString(hasher.Sum(nil))
			log.Printf("Peer certHash:  -->  %s\n", clientCertificateHash)
		} else {
			fmt.Println("No peer certificates sent")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		event := &stsRequest{}

		contentType := r.Header.Get("Content-type")

		switch {
		case contentType == "application/json":
			err := json.NewDecoder(r.Body).Decode(event)
			if err != nil {
				fmt.Printf("Could Not parse application/json payload: %v", err)
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
		case contentType == "application/x-www-form-urlencoded":
			err := r.ParseForm()
			if err != nil {
				fmt.Printf("Could not parse application/x-www-form-urlencode Form: %v", err)
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
			v := r.Form

			event = &stsRequest{
				GrantType:        v.Get("grant_type"),
				Resource:         v.Get("resource"),
				Audience:         v.Get("audience"),
				Scope:            v.Get("scope"),
				SubjectToken:     v.Get("subject_token"),
				SubjectTokenType: v.Get("subject_token_type"),
				ActorToken:       v.Get("actor_token"),
				ActorTokenType:   v.Get("actor_token_type"),
			}
		default:
			fmt.Printf("Invalid Content Type [%s]", contentType)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		newCtx := context.WithValue(ctx, contextEventKey, *event)
		newCtx = context.WithValue(newCtx, contextCertificateHashKey, clientCertificateHash)
		h.ServeHTTP(w, r.WithContext(newCtx))
	})
}

func verifyAuthToken(ctx context.Context, rawToken string) bool {
	return true
}

func tokenhandlerpost(w http.ResponseWriter, r *http.Request) {

	val := r.Context().Value(contextKey("event")).(stsRequest)

	if val.GrantType == "" || val.SubjectToken == "" || val.SubjectTokenType == "" {

		fmt.Printf("Invalid Request Payload Headers: \n %v\n", val)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if !isValidTokenType(val.SubjectTokenType) {
		fmt.Printf("Invalid subject_token_type: %s", val.SubjectTokenType)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if val.ActorTokenType != "" && !isValidTokenType(val.ActorTokenType) {
		log.Printf("Invalid actor_token_type: %s", val.ActorTokenType)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	clientCertificateHash := r.Context().Value(contextKey("certificateHash")).(string)
	fmt.Printf("  %v\n", clientCertificateHash)

	c := CNF{
		X5T: clientCertificateHash,
	}

	/*
		   Verify Alice and Bob's provided token and certificate the should be using...
			Alice's token is iamtheeggman  with cert hash A7iOckLIMP4o8YXW4voDTxGKguoTAu39TvBmtRi2jw4=
			Bob's token is iamthewalrus with cert hash CMDVBKa48HndDNK1B8X/VAPQbYqANjaZh8mIeehwHgI=
	*/

	var subject string
	switch val.SubjectToken {
	case "iamtheeggman":
		if clientCertificateHash != "A7iOckLIMP4o8YXW4voDTxGKguoTAu39TvBmtRi2jw4=" {
			log.Printf("Provided client certificate for user does not match")
			http.Error(w, "Provided client certificate for user does not match", http.StatusUnauthorized)
			return
		}
		subject = "alice"
	case "iamthewalrus":
		if clientCertificateHash != "CMDVBKa48HndDNK1B8X/VAPQbYqANjaZh8mIeehwHgI=" {
			log.Printf("Provided client certificate for user does not match")
			http.Error(w, "Provided client certificate for user does not match", http.StatusUnauthorized)
			return
		}
		subject = "bob"

	default:
		log.Printf("Provided subjectToken is does not match any passphrase")
		http.Error(w, "Provided subjectToken is does not match any passphrase", http.StatusForbidden)
		return
	}

	claims := &CustomClaimsExample{
		&jwt.RegisteredClaims{
			Issuer:    "https://sts.domain.com",
			Audience:  []string{val.Audience},
			Subject:   subject,
			IssuedAt:  &jwt.NumericDate{time.Now()},
			ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Hour * 24 * 356)},
		},
		c,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = *jwtKeyID
	ss, err := token.SignedString(jwtKey)
	if err != nil {
		fmt.Printf("Could not sign JWT %v\n", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	p := &TokenResponse{
		AccessToken:     ss,
		IssuedTokenType: AccessToken,
		TokenType:       "Bearer",
		ExpiresIn:       int64(60),
	}
	fmt.Printf("Response Data: %v", p)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store")

	err = json.NewEncoder(w).Encode(p)
	if err != nil {
		fmt.Printf("Could not marshall JSON to output %v\n", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
}

func main() {
	flag.Parse()

	router := mux.NewRouter()
	router.Path("/token").Methods(http.MethodPost).HandlerFunc(tokenhandlerpost)

	clientCaCert, err := os.ReadFile(*tlsCA)
	if err != nil {
		panic(err)
	}
	clientCaCertPool := x509.NewCertPool()
	clientCaCertPool.AppendCertsFromPEM(clientCaCert)

	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCaCertPool,
	}

	keyData, err := os.ReadFile(*jwtPrivateKey)
	if err != nil {
		log.Fatalf("Error reading JWT verification private key: %v", err)
	}
	jwtKey, err = jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		log.Fatalf("Error parsing JWT verification key private key: %v", err)
	}

	server = &http.Server{
		Addr:      *port,
		Handler:   eventsMiddleware(router),
		TLSConfig: tlsConfig,
	}

	http2.ConfigureServer(server, &http2.Server{})
	fmt.Println("Starting Server..")

	err = server.ListenAndServeTLS(*tlsCert, *tlsKey)
	fmt.Printf("Unable to start Server %v", err)

}
