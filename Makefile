build:
	go build ./cmd/canarytail
static:
	CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' ./cmd/canarytail
clean:
	rm -f canarytail