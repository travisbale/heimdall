-include .env
export

build:
	CGO_ENABLED=0 GOOS=linux go build -o bin/heimdall ./cmd/heimdall/main.go
