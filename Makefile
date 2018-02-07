test:
	go test --race
	go test --race ./jwt
	go test --race ./jwt/ed25519

cover:
	rm -f *.coverprofile
	go test -coverprofile=auth.coverprofile
	go test -coverprofile=jwt.coverprofile ./jwt
	go test -coverprofile=ed25519.coverprofile ./jwt/ed25519
	gover
	go tool cover -html=gover.coverprofile
	rm -f *.coverprofile

.PHONY: test cover
