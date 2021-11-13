build:
	go build -o canarytail ./cmd/canarytail.go
build_all:
	GOOS=windows GOARCH=amd64 go build -o canarytail-windows-amd64.exe ./cmd/canarytail.go
	GOOS=linux GOARCH=amd64 go build -o canarytail-linux-amd64 ./cmd/canarytail.go
	GOOS=darwin GOARCH=amd64 go build -o canarytail-darwin-amd64 ./cmd/canarytail.go
	GOOS=darwin GOARCH=arm64 go build -o canarytail-darwin-arm64 ./cmd/canarytail.go
static:
	CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' ./cmd/canarytail
clean:
	rm -f canarytail
