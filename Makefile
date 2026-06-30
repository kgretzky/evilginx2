TARGET=evilginx

.PHONY: all build test test-race vet clean
all: build

build:
	@go build -o ./build/$(TARGET) -mod=vendor main.go

test:
	@go test -mod=vendor ./...

test-race:
	@go test -race -mod=vendor ./...

vet:
	@go vet -mod=vendor ./...

clean:
	@go clean
	@rm -f ./build/$(TARGET)
