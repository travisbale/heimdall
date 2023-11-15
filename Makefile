-include .env
export

build:
	CGO_ENABLED=0 GOOS=linux go build -o bin/heimdall -buildvcs=false ./cmd/.
