all: test-all
ci: pre-build test

pre-build:
	go get ./p3lib-sphinx

test-all:
	make test-sphinx

test-sphinx: 
	go vet ./p3lib-sphinx
	go test ./p3lib-sphinx/... -cover
