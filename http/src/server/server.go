package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"

	"net/http"
	"strings"

	//"net/http/httputil"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"golang.org/x/net/http2"
)

var (
	port    = flag.String("port", ":8443", "port")
	tlsCert = flag.String("tlsCert", "server.crt", "Server Certificate")
	tlsKey  = flag.String("tlsKey", "server.key", "Server Key")
	tlsCA   = flag.String("tlsCA", "tls-ca.crt", "Client Certificate CA")
	jwkFile = flag.String("jwkFile", "jwk.key", "JWK file")
	server  *http.Server

	jwtSet jwk.Set
)

const ()

type contextKey string

const contextEventKey contextKey = "event"

type CNF struct {
	X5T string `json:"x5t#S256,omitempty"`
}

type CustomClaimsExample struct {
	*jwt.RegisteredClaims
	CNF `json:"cnf"`
}

type parsedData struct {
	Msg string `json:"msg"`
}

func getKey(token *jwt.Token) (interface{}, error) {
	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have string kid")
	}
	if key, ok := jwtSet.LookupKeyID(keyID); ok {
		var raw interface{}
		if err := key.Raw(&raw); err != nil {
			return nil, err
		}
		return raw, nil
	}
	return nil, errors.New("unable to find key")
}

func eventsMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		splitToken := strings.Split(authHeader, "Bearer")
		if len(splitToken) == 2 {
			tok := strings.TrimSpace(splitToken[1])

			token, err := jwt.ParseWithClaims(tok, &CustomClaimsExample{}, getKey)
			if err != nil {
				http.Error(w, "Could ot parse jwt", http.StatusUnauthorized)
				return
			}
			claims, ok := token.Claims.(*CustomClaimsExample)
			if !ok {
				http.Error(w, "Could ot verify  parse as token bound jwt", http.StatusUnauthorized)
				return
			}

			if !token.Valid {
				http.Error(w, "Could ot verify jwt", http.StatusUnauthorized)
				return
			}

			fmt.Printf("Bound Certificate Hash: %s\n", claims.CNF.X5T)

			var clientCertificateHash string
			if len(r.TLS.PeerCertificates) > 0 {
				v := r.TLS.PeerCertificates[0]
				hasher := sha256.New()
				hasher.Write(v.Raw)
				clientCertificateHash = base64.StdEncoding.EncodeToString(hasher.Sum(nil))
				//log.Printf("Peer certHash:  -->  %s\n", clientCertificateHash)
			} else {
				fmt.Println("No peer certificates sent")
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			if claims.CNF.X5T == clientCertificateHash {
				fmt.Printf("Certificate hash matched\n")
			} else {
				fmt.Printf("Peer certificate does not match certificate hash in claims\n")
				http.Error(w, "Peer certificate does not match certificate hash in claims\n", http.StatusUnauthorized)
				return
			}

			event := &parsedData{
				Msg: claims.Subject,
			}

			ctx := context.WithValue(r.Context(), contextEventKey, *event)
			h.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	})
}

func gethandler(w http.ResponseWriter, r *http.Request) {

	val := r.Context().Value(contextKey("event")).(parsedData)
	fmt.Printf("Found user: %s\n", val.Msg)
	fmt.Fprint(w, fmt.Sprintf("%s ok", val))
}

func main() {

	flag.Parse()

	router := mux.NewRouter()
	router.Methods(http.MethodGet).Path("/").HandlerFunc(gethandler)

	clientCaCert, err := os.ReadFile(*tlsCA)
	if err != nil {
		fmt.Printf("did not read tlsCA: %v", err)
		return
	}

	jwkBytes, err := os.ReadFile(*jwkFile)
	if err != nil {
		fmt.Printf("did not read tlsCA: %v", err)
		return
	}

	jwtSet, err = jwk.Parse(jwkBytes)
	if err != nil {
		fmt.Printf("Unable to load JWK Set: %s", err)
		return
	}

	clientCaCertPool := x509.NewCertPool()
	clientCaCertPool.AppendCertsFromPEM(clientCaCert)

	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCaCertPool,
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
