APP_NAME=auth-service
VERSION=$(shell git describe --tags --abbrev=0 2>/dev/null || echo "latest")

test:
	cd internal/tests/tests && go test -v ./...

build:
	go build -o $(APP_NAME) ./cmd/server

docker-build:
	docker build -t $(APP_NAME):$(VERSION) .

docker-run: docker-build
	docker-compose up

clean:
	rm -f $(APP_NAME)
	docker-compose down