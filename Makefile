all: test-all
ci: pre-build test

pre-build:
	go get ./sphinx
	go get ./sphinx/crypto

test-all:
	make test-sphinx

test-sphinx: 
	go vet ./sphinx
	go test ./sphinx/... -cover
