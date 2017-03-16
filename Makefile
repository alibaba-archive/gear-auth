test:
	go test --race
	go test --race ./jwt

cover:
	rm -f *.coverprofile
	go test -coverprofile=auth.coverprofile
	go test -coverprofile=jwt.coverprofile ./jwt
	gover
	go tool cover -html=gover.coverprofile
	rm -f *.coverprofile

.PHONY: test cover
