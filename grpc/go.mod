module main

go 1.15

require (
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/lestrrat-go/jwx/v2 v2.0.1
	github.com/salrashid123/scratchpad/go_cert_bound_sts/grpc/echo v0.0.0
	github.com/salrashid123/sts/grpc v0.0.0-20220914004521-ab064d139346
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2
	google.golang.org/grpc v1.49.0

)

replace github.com/salrashid123/scratchpad/go_cert_bound_sts/grpc/echo => ./src/echo
