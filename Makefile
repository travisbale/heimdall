-include .env
export

build:
	go build -o bin/heimdall ./cmd/heimdall/*
