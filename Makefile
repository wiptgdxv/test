.PHONY: fmt test race vet build run-server run-client compose-up compose-client compose-down

fmt:
	gofmt -w ./cmd ./internal

test:
	go test -buildvcs=false ./...

race:
	go test -buildvcs=false -race ./...

vet:
	go vet ./...

build:
	go build -buildvcs=false -trimpath -o bin/server ./cmd/server
	go build -buildvcs=false -trimpath -o bin/client ./cmd/client

run-server:
	go run ./cmd/server serve

run-client:
	go run ./cmd/client -input testdata/sample-input.json

compose-up:
	docker compose up -d --build server

compose-client:
	docker compose run --rm client -input /data/sample-input.json

compose-down:
	docker compose down
