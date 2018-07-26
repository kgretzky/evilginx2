TARGET=evilginx
PACKAGES=core database log parser

.PHONY: all
all: deps build

deps: godep
		@dep ensure

build:
		@go build -o ./bin/$(TARGET) main.go

clean:
		@go clean
		@rm -f ./bin/$(TARGET)

install:
		@mkdir -p /usr/share/evilginx/phishlets
		@cp ./phishlets/* /usr/share/evilginx/phishlets/
		@cp ./bin/$(TARGET) /usr/local/bin

godep:
		@go get -u github.com/golang/dep/...
