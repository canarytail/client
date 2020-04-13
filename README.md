# CanaryTail CLI
> CanaryTail CLI is a simple proof-of-concept implementation of the [CanaryTail standard](https://github.com/canarytail/standard)

## Installation

### OS X & Linux:

In order to build, make sure you have `go` installed and the `GOPATH` set to its location (skip this if you already know how to use `go`).

```sh
export GOROOT=$HOME/go
export PATH=$PATH:$GOROOT/bin
```

Build the project from the source folder for this canarytail client repo

```sh
 go build ./cmd/canarytail
```

Run it via `./canarytail`, which should return:

```sh
Usage:
	canarytail https://www.example.com/canary.txt
```

## Release History

* 0.1+2
    * Updated readme
* 0.1
    * golang CLI for PoC

## Contributing

1. Fork it (<https://github.com/canarytail/client/fork>)
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request
