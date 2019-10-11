TARGET=evilginx
PACKAGES=core database log parser

.PHONY: all
all: build

build:
		@go build -o ./bin/$(TARGET) -mod=vendor

clean:
		@go clean
		@rm -f ./bin/$(TARGET)

install:
		@mkdir -p /usr/share/evilginx/phishlets
		@cp ./phishlets/* /usr/share/evilginx/phishlets/
		@cp ./bin/$(TARGET) /usr/local/bin
