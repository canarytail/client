# CanaryTail CLI
> CanaryTail CLI is a simple proof-of-concept implementation of the [CanaryTail standard](https://github.com/canarytail/standard)

## How to use

This assumes you have already downloaded or built the binary for canarytail. If you haven't, skip to [Installation](#installation).

### Init

Canarytail requires a place to store keys and the history of the canaries you generate or verify. Define this place automatically by initializing.

`./canarytail init`

### Create a signing key

Canaries need to be signed by their author and associated with a specific website or project name, so you must tell canarytail the domain name of the website, or if you don't have publishing access to the domain's root folder (e.g. mydomain.com/canary.json), you can tell canarytail the name of the asset the canary is for instead.

`./canarytail key new mydomain.com`

`./canarytail key new myyoutubeaccount`

### Generating the canary

You can generate the canary by using the following:

`./canarytail canary new mydomain.com`

`./canarytail canary new myyoutubeaccount`


## Installation

The steps below allow you to compile from the source code. If you prefer using an already pre-compiled binary, see the [releases](https://github.com/canarytail/client/releases) page.

### Windows:

In order to build in Windows, make sure you have `go` installed and the `GOPATH` set to its location.

#### In PowerShell

To build the binary for use **on Windows**:
```
$Env:GOOS="windows"; $Env:GOARCH="amd64"; go build -o canarytail-windows-amd64.exe ./cmd/
```

To build the binary for use **on Linux**:
```
$Env:GOOS="linux"; $Env:GOARCH="amd64"; go build -o canarytail-linux-amd64 ./cmd/
```

To build the binary for use **on Mac**:
```
$Env:GOOS="darwin"; $Env:GOARCH="amd64"; go build -o canarytail-darwin-amd64 ./cmd/
```

Now just run the `canarytail-dist-amd64` binary you built on whatever OS you built it for.

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

Run it via `./canarytail`


### Command line arguments

```sh
Usage: ./canarytail command [SUBCOMMAND] [OPTIONS]

Commands:
  help		                  Display this help message or help on a command

  init		                  Initialize config and keys to $CANARY_HOME
  key

      This command is for manipulating cryptographic keys.

      new DOMAIN              Generates a new key for signing canaries and saves
                              to $CANARY_HOME/DOMAIN

  canary

      This command is for manipulating canaries.

      new DOMAIN [--OPTIONS]
                              Generates a new canary, signs it using the key located
                              in $CANARY_HOME/DOMAIN, and saves to that same path.

                              Codes provided in OPTIONS will be removed from the canary,
                              signifying that event has tripped the canary.

      update DOMAIN [--OPTIONS]
                              Updates the existing canary named DOMAIN. If no OPTIONS
                              are provided, it merely updates the signature date. If
                              no EXPIRY is provided, it reuses the previous value
                              (e.g. renewing for a month).

                              Codes provided in OPTIONS will be removed from the canary,
                              signifying that event has tripped the canary.
                              

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

New canary signing key               ./canarytail key new mydomain.com
New canary with defaults             ./canarytail canary new mydomain.com      
Renew existing canary 30 more days   ./canarytail canary update mydomain.com
Trip canary for warrant              ./canarytail canary update mydomain.com --WAR
Validate a canary on a site          ./canarytail canary validate https://mydomain.com/canary.json
Validate a canary locally            ./canarytail canary validate ~/canary.json
```



## Contributing

1. Fork it (<https://github.com/canarytail/client/fork>)
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request

