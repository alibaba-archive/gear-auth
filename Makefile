test:
	go test --race
	go test --race ./crypto
	go test --race ./jwt
	go test --race ./pbkdf2

cover:
	rm -f *.coverprofile
	go test -coverprofile=auth.coverprofile
	go test -coverprofile=crypto.coverprofile ./crypto
	go test -coverprofile=jwt.coverprofile ./jwt
	go test -coverprofile=pbkdf2.coverprofile ./pbkdf2
	gover
	go tool cover -html=gover.coverprofile
	rm -f *.coverprofile

.PHONY: test cover
