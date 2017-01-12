test:
	go test --race

cover:
	rm -f *.coverprofile
	go test -coverprofile=gear-auth.coverprofile
	go tool cover -html=gear-auth.coverprofile
	rm -f *.coverprofile

doc:
	godoc -http=:6060

.PHONY: test cover doc
