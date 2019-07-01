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

Prerequisite: [Docker](https://docs.docker.com/install/)

```
git clone https://github.com/zombiezen/sandpass.git
cd sandpass
```

Running as a normal HTTP server:

```
docker build -t sandpass .
docker run --rm -p 8080:8080 sandpass
```

Packaging as a Sandstorm app (requires [docker-spk][]):

```
docker-spk build
```

[docker-spk]: https://github.com/zenhack/docker-spk

## License

Apache 2.0. See the LICENSE file for details. Vendored libraries are released
under their respective licenses.
