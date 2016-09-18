# Sandpass

Sandpass is a web-based password manager based on the [KeePass][keepass]
database format that runs on [Sandstorm][sandstorm].

Sandpass has not undergone a formal security review: use at your own risk.

[keepass]: http://keepass.info/
[sandstorm]: https://sandstorm.io/

## Installing

Install Sandpass from [the Sandstorm App Market][sandpass-app-market],
or grab the SPK from the [releases][releases] page.

[sandpass-app-market]: https://apps.sandstorm.io/app/rq41p170hcs5rzg66axggv8r90fjcssdky8891kq5s7jcpm1813h
[releases]: https://github.com/zombiezen/sandpass/releases

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
