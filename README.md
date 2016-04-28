# Sandpass

Sandpass is a web-based password manager based on the Keepass database format
that runs on [Sandstorm](https://sandstorm.io/).

Sandpass is still under development, so expect some rough edges. As such,
Sandpass has not undergone a formal security review.

## Installing

Once Sandpass is released on the [Sandstorm App Market][app-market], it will be
a one-click install.  In the meantime, you can download an SPK from one of the
[releases][releases] and upload it to [Oasis][oasis] or your own Sandstorm
server by using the "Upload..." button under the Apps tab.

[app-market]: https://apps.sandstorm.io/
[releases]: https://github.com/zombiezen/sandpass/releases
[oasis]: https://oasis.sandstorm.io/

## Developing

Prerequisite: [Go 1.6](https://golang.org/dl/)

```
go get zombiezen.com/go/sandpass
cd $GOPATH/zombiezen.com/go/sandpass
```

Running as a normal HTTP server:

```
sandpass -db=foo.db -listen=localhost:8080 -permissions=false
```

Running as a Sandstorm app (requires [vagrant-spk][vagrant-spk-install]):

```
vagrant-spk dev
```

[vagrant-spk-install]: https://docs.sandstorm.io/en/latest/vagrant-spk/installation/

## License

Apache 2.0. See the LICENSE file for details. Vendored libraries are released
under their respective licenses.
