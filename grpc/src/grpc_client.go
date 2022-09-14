package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/salrashid123/scratchpad/go_cert_bound_sts/grpc/echo"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	//sts "google.golang.org/grpc/credentials/sts"
	sts "github.com/salrashid123/sts/grpc"
)

const ()

var (
	conn *grpc.ClientConn
)

func main() {

	address := flag.String("host", "localhost:50051", "host:port of gRPC server")
	tlsCA := flag.String("tlsCA", "tls-ca.crt", "CACert for server")
	tlsCert := flag.String("tlsCert", "client.crt", "TLS Client Certificate")
	tlsKey := flag.String("tlsKey", "client.key", "TLS Client Key")

	stsaddress := flag.String("stsaddress", "https://sts.domain.com:8081/token", "STS Server address")
	stsaudience := flag.String("stsaudience", "grpcs://grpc.domain.com:50051", "the audience and resource value to send to STS server")
	scope := flag.String("scope", "https://www.googleapis.com/auth/cloud-platform", "scope to send to STS server")

	stsCred := flag.String("stsCred", "/tmp/cred.txt", "STS Credentials (as file)")

	serverName := flag.String("servername", "grpc.domain.com", "SNI for the grpcEndpoint")
	stsSNIServerName := flag.String("stsSNIServerName", "sts.domain.com", "SNI for the STS Server")
	flag.Parse()

	var err error

	caCert, err := ioutil.ReadFile(*tlsCA)
	if err != nil {
		log.Fatalf("did not read tlsCA: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	clientCerts, err := tls.LoadX509KeyPair(
		*tlsCert,
		*tlsKey,
	)
	if err != nil {
		log.Fatalf("did not load keypairs: %v", err)
	}

	tlsConfig := tls.Config{
		ServerName:   *serverName,
		Certificates: []tls.Certificate{clientCerts},
		RootCAs:      caCertPool,
	}

	creds := credentials.NewTLS(&tlsConfig)

	stlsConfig := tls.Config{
		ServerName:   *stsSNIServerName,
		Certificates: []tls.Certificate{clientCerts},
		RootCAs:      caCertPool,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &stlsConfig,
		},
	}
	//fmt.Printf("%v", stlsConfig)
	// https://github.com/grpc/grpc-go/issues/5099

	stscreds, err := sts.NewCredentials(sts.Options{
		TokenExchangeServiceURI: *stsaddress,
		Resource:                *stsaudience,
		Audience:                *stsaudience,
		Scope:                   *scope,
		SubjectTokenPath:        *stsCred,
		SubjectTokenType:        "urn:ietf:params:oauth:token-type:access_token",
		RequestedTokenType:      "urn:ietf:params:oauth:token-type:jwt",
		HTTPClient:              client,
	})
	if err != nil {
		log.Fatalf("unable to create TokenSource: %v", err)
	}

	conn, err = grpc.Dial(*address, grpc.WithTransportCredentials(creds), grpc.WithPerRPCCredentials(stscreds))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	c := echo.NewEchoServerClient(conn)
	ctx := context.Background()

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{Service: "echo.EchoServer"})
	if err != nil {
		log.Fatalf("HealthCheck failed %v", err)
	}

	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		log.Fatalf("service not in serving state: ", resp.GetStatus().String())
	}
	log.Printf("RPC HealthChekStatus:%v", resp.GetStatus())

	r, err := c.SayHello(ctx, &echo.EchoRequest{Name: "unary RPC msg "})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	time.Sleep(1 * time.Second)
	log.Printf("RPC Response: %s", r)

}
