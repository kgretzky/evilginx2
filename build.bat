@echo off
set GOARCH=amd64
echo Building...
go build -o .\build\evilginx.exe -mod=vendor
