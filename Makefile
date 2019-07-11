all: test-all
ci: pre-build test

pre-build:
	go get ./sphinx
	go get ./sphinx/crypto
	go get ./fullrt
	go get ./sinkhole
#	go get ./octopusdht

test-all:
	make test-sphinx
	make test-fullrt
	make test-sinkhole
#	make test-octopusdht

test-sphinx: 
	go vet ./sphinx
	go test ./sphinx/... -cover

#test-octopusdht: 
#	go vet ./octopusdht
#	go test ./octopusdht/... -cover

test-fullrt: 
	go vet ./fullrt
	go test ./fullrt/... -cover

test-sinkhole: 
	go vet ./sinkhole
	go test ./sinkhole/... -cover
