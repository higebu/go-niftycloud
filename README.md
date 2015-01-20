# go-niftycloud

[![Build Status](https://travis-ci.org/higebu/go-niftycloud.svg)](https://travis-ci.org/higebu/go-niftycloud)
[![GoDoc](https://godoc.org/github.com/higebu/niftycloud?status.svg)](https://godoc.org/github.com/higebu/niftycloud)

*CAUTION: EXPERIMENTAL CODE*

The _go-niftycloud_ package enables Go programs to interact with NIFTY Cloud.

This is built on [github.com/goamz/goamz](https://github.com/goamz/goamz).

## Installing

```
go get github.com/higebu/go-niftycloud/niftycloud
go get github.com/higebu/go-niftycloud/compute
```

## Environment variables

Currently _go-niftycloud_ supports following variables.

* `NIFTY_CLOUD_ACCESS_KEY`
* `NIFTY_CLOUD_SECRET_KEY`
* `NIFTY_CLOUD_MAX_RETRY`
* `NIFTY_CLOUD_CONNECTION_TIMEOUT`
* `NIFTY_CLOUD_SOCKET_TIMEOUT`

## Example

There are examples in [higebu/go-niftycloud-examples](https://github.com/higebu/go-niftycloud-examples).

## Running tests

To run tests, first install gocheck with:

`$ go get gopkg.in/check.v1`

Then run go test as usual:

`$ go test github.com/higebu/go-niftycloud/...`

_Note:_ running all tests with the command `go test ./...` will currently fail as tests do not tear down their HTTP listeners.

If you want to run integration tests (costs money), set up the EC2 environment variables as usual, and run:

`$ gotest -i`

## License

Licensed under the GNU Lesser General Public License, version 3.0.
