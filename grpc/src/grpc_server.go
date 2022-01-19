package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"

	"github.com/salrashid123/scratchpad/go_cert_bound_sts/grpc/echo"

	"crypto/sha256"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/golang-jwt/jwt"
	"github.com/lestrrat/go-jwx/jwk"
	"google.golang.org/grpc/metadata"
)

type CNF struct {
	X5T string `json:"x5t#S256,omitempty"`
}

type CustomClaimsExample struct {
	*jwt.StandardClaims
	CNF `json:"cnf"`
}

type contextKey string

const contextEventKey contextKey = "event"

type parsedData struct {
	Msg string `json:"msg"`
}

var (
	grpcport = flag.String("grpcport", ":50051", "grpcport")
	tlsCert  = flag.String("tlsCert", "grpc.crt", "Server Certificate")
	tlsKey   = flag.String("tlsKey", "grpc.key", "Server Key")
	tlsCA    = flag.String("tlsCA", "tls-ca.crt", "Client Certificate CA")
	jwkFile  = flag.String("jwkFile", "jwk.key", "JWK file")
	hs       *health.Server

	jwtSet *jwk.Set
	conn   *grpc.ClientConn
)

const (
	address string = ":50051"
)

type server struct {
	echo.UnimplementedEchoServerServer
}

func authUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if len(md["authorization"]) > 0 {
		reqToken := md["authorization"][0]
		splitToken := strings.Split(reqToken, "Bearer")
		reqToken = strings.TrimSpace(splitToken[1])

		token, err := jwt.ParseWithClaims(reqToken, &CustomClaimsExample{}, getKey)
		if err != nil {
			return nil, grpc.Errorf(codes.Unauthenticated, "Could not extract parse jwt %v", err)
		}
		claims, ok := token.Claims.(*CustomClaimsExample)
		if !ok {
			return nil, grpc.Errorf(codes.Unauthenticated, "Could not extract custom claims from jwt")
		}

		if !token.Valid {
			return nil, grpc.Errorf(codes.Unauthenticated, "JWT not valid")
		}

		var clientCertificateHash string
		peer, ok := peer.FromContext(ctx)
		if ok {
			tlsInfo := peer.AuthInfo.(credentials.TLSInfo)
			log.Printf("Peer SerialNumber:  -->  %v\n", tlsInfo.State.VerifiedChains[0][0].SerialNumber)
			v := tlsInfo.State.PeerCertificates[0]
			hasher := sha256.New()
			hasher.Write(v.Raw)
			clientCertificateHash = base64.StdEncoding.EncodeToString(hasher.Sum(nil))
		} else {
			return nil, grpc.Errorf(codes.Unauthenticated, "Could not extract cert hash from peer")
		}

		if claims.CNF.X5T == clientCertificateHash {
			fmt.Printf("Certificate hash matched\n")
		} else {
			return nil, grpc.Errorf(codes.Unauthenticated, "certificate hash and JWT claims do not match")
		}

		event := &parsedData{
			Msg: claims.Subject,
		}

		newCtx := context.WithValue(ctx, contextKey("event"), event)
		return handler(newCtx, req)
	}
	return nil, grpc.Errorf(codes.Unauthenticated, "Authorization header not provided")

}

func getKey(token *jwt.Token) (interface{}, error) {
	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have string kid")
	}
	if key := jwtSet.LookupKeyID(keyID); len(key) == 1 {
		return key[0].Materialize()
	}
	return nil, errors.New("unable to find key")
}

func (s *server) SayHello(ctx context.Context, in *echo.EchoRequest) (*echo.EchoReply, error) {

	log.Println("Got rpc: --> ", in.Name)
	ev := ctx.Value(contextKey("event")).(*parsedData)
	log.Println(" with verified Subject: --> ", ev.Msg)

	var h, err = os.Hostname()
	if err != nil {
		log.Fatalf("Unable to get hostname %v", err)
	}
	return &echo.EchoReply{Message: "Hello " + in.Name + "  from hostname " + h}, nil
}

type healthServer struct{}

func (s *healthServer) Check(ctx context.Context, in *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	log.Printf("Handling grpc Check request")
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

func (s *healthServer) Watch(in *healthpb.HealthCheckRequest, srv healthpb.Health_WatchServer) error {
	return status.Error(codes.Unimplemented, "Watch is not implemented")
}

func main() {

	flag.Parse()

	if *grpcport == "" {
		fmt.Fprintln(os.Stderr, "missing -grpcport flag (:50051)")
		flag.Usage()
		os.Exit(2)
	}

	clientCaCert, err := ioutil.ReadFile(*tlsCA)
	if err != nil {
		log.Fatalf("could not load tlsCA: %s", err)
	}

	clientCaCertPool := x509.NewCertPool()
	clientCaCertPool.AppendCertsFromPEM(clientCaCert)

	certificate, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
	if err != nil {
		log.Fatalf("could not load server key pair: %s", err)
	}

	customVerify := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		for _, rawCert := range rawCerts {
			c, _ := x509.ParseCertificate(rawCert)
			log.Printf("Conn Serial Number [%d]\n", c.SerialNumber)
		}
		return nil
	}
	fmt.Printf("%v", customVerify)

	tlsConfig := tls.Config{
		ClientAuth:            tls.RequireAndVerifyClientCert,
		Certificates:          []tls.Certificate{certificate},
		VerifyPeerCertificate: customVerify,
		ClientCAs:             clientCaCertPool,
	}
	creds := credentials.NewTLS(&tlsConfig)

	jwkBytes, err := ioutil.ReadFile(*jwkFile)
	if err != nil {
		fmt.Printf("did not read tlsCA: %v", err)
		return
	}

	jwtSet, err = jwk.Parse(jwkBytes)
	if err != nil {
		fmt.Printf("Unable to load JWK Set: ", err)
		return
	}

	lis, err := net.Listen("tcp", *grpcport)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	sopts := []grpc.ServerOption{grpc.MaxConcurrentStreams(10)}

	sopts = append(sopts, grpc.Creds(creds))

	sopts = append(sopts, grpc.UnaryInterceptor(authUnaryInterceptor))
	sopts = append(sopts)

	s := grpc.NewServer(sopts...)

	echo.RegisterEchoServerServer(s, &server{})

	healthpb.RegisterHealthServer(s, &healthServer{})

	log.Printf("Starting gRPC Server at %s", *grpcport)
	s.Serve(lis)

}
