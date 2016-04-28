# Sandpass

Sandpass is a web-based password manager based on the Keepass database format
that runs on [Sandstorm](https://sandstorm.io/).

Sandpass is still under development, so expect some rough edges. As such,
Sandpass has not undergone a formal security review.

## Installing

Once Sandpass is released on the Sandstorm App Market, it will be as simple as
one click to Demo and Install on Oasis.

## Building

Prerequisite: [Go 1.6](https://golang.org/dl/)

```
go get zombiezen.com/go/sandpass
cd $GOPATH/zombiezen.com/go/sandpass
```

Running as a normal HTTP server:

```
sandpass -db=foo.db -listen=localhost:8080 -permissions=false
```

Running as a Sandstorm app (requires [vagrant-spk](https://docs.sandstorm.io/en/latest/vagrant-spk/installation/)):

```
vagrant-spk dev
```

## License

Apache 2.0. See the LICENSE file for details. Vendored libraries are released
under their respective licenses.
