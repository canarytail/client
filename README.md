# CanaryTail CLI
> CanaryTail CLI is a simple proof-of-concept implementation of the [CanaryTail standard](https://github.com/canarytail/standard)

## Installation

### OS X & Linux:

*Skip this step if you already know how to use `go`*

In order to build, make sure you have `go` installed and the `GOPATH` set to its location. It will likely be `/usr/local/go`. Replace the example below with your `go` location.

```sh
export GOROOT=/usr/local/go
export PATH=$PATH:$GOROOT/bin
```

Build the project from the source folder for this canarytail client repo

```sh
 go build ./cmd/canarytail.go
```

Run it via `./canarytail`, which should return:

```sh
Usage:
	canarytail https://www.example.com/canary.txt
```

## Contributing

1. Fork it (<https://github.com/canarytail/client/fork>)
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request

