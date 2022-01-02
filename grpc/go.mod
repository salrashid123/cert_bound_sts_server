module main

go 1.15

require (
	github.com/aws/aws-sdk-go-v2/service/sts v1.12.0
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/lestrrat/go-jwx v0.9.1
	github.com/salrashid123/scratchpad/go_cert_bound_sts/grpc/echo v0.0.0
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	google.golang.org/grpc v1.33.2

)

replace github.com/salrashid123/scratchpad/go_cert_bound_sts/grpc/echo => ./src/echo
