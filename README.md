# CanaryTail CLI
> CanaryTail CLI is a simple proof-of-concept implementation of the [CanaryTail standard](https://github.com/canarytail/standard)

## Installation

### Windows:

```
$Env:GOOS="windows"; $Env:GOARCH="amd64"; go build -o canarytail-windows-amd64.exe ./cmd/
$Env:GOOS="linux"; $Env:GOARCH="amd64"; go build -o canarytail-linux-amd64 ./cmd/
$Env:GOOS="darwin"; $Env:GOARCH="amd64"; go build -o canarytail-darwin-amd64 ./cmd/
```

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
Usage: ./canarytail command [SUBCOMMAND] [OPTIONS]

Commands:
  help		                  Display this help message or help on a command

  init		                  Initialize config and keys to $CANARY_HOME
  key

      This command is for manipulating cryptographic keys.

      new ALIAS               Generates a new key for signing canaries and saves
                              to $CANARY_HOME/ALIAS

  canary

      This command is for manipulating canaries.

      new ALIAS [--OPTIONS]
                              Generates a new canary, signs it using the key located
                              in $CANARY_HOME/ALIAS, and saves to that same path.

                              Codes provided in OPTIONS will be removed from the canary,
                              signifying that event has triggered the canary.

      update ALIAS [--OPTIONS]
                              Updates the existing canary named ALIAS. If no OPTIONS
                              are provided, it merely updates the signature date. If
                              no EXPIRY is provided, it reuses the previous value
                              (e.g. renewing for a month).

                              Codes provided in OPTIONS will be removed from the canary,
                              signifying that event has triggered the canary.
                              

      Valid OPTIONS:

      --expiry:#              Expires in # minutes from now (default: 43200, one month)
      --cease                 Court order to cease operations
      --duress                Under duress (coercion, blackmail, etc)
      --gag                   Gag order received
      --raid                  Raided, but data unlikely compromised
      --seize                 Hardware or data seized, unlikely compromised
      --subp                  Subpoena received
      --trap                  Trap and trace order received
      --war                   Warrant received
      --xcred                 Compromised credentials
      --xopers                Operations compromised

      validate [URI]              Validates a canary's signature

  version	                  Show version and exit

Environment:
  CANARY_HOME	Location of canarytail config and files (default: $PWD)


Usage examples:

New canary signing key               ./canarytail key new mydomain
New canary with defaults             ./canarytail canary new mydomain       
Renew existing canary 30 more days   ./canarytail canary update mydomain
Trigger canary for warrant           ./canarytail canary update mydomain --WAR
Validate a canary on a site          ./canarytail canary validate https://mydomain/canary.json
Validate a canary locally            ./canarytail canary validate ~/canary.json
```



## Contributing

1. Fork it (<https://github.com/canarytail/client/fork>)
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request

