.PHONY: build web test lint demo docker

build: web
	CGO_ENABLED=0 go build -trimpath -o bin/honeynet ./cmd/honeynet

web:
	cd web && npm ci && npm run build

test:
	go test -race ./...
	cd web && npm test

lint:
	go vet ./...
	test -z "$$(gofmt -l .)"
	cd web && npm run typecheck

demo: build
	./bin/honeynet -demo

docker:
	docker build -t honeynet .
