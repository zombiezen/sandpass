@0xba54be93d5898b97;

using Spk = import "/sandstorm/package.capnp";

const pkgdef :Spk.PackageDefinition = (
  # The package definition. Note that the spk tool looks specifically for the
  # "pkgdef" constant.

  id = "rq41p170hcs5rzg66axggv8r90fjcssdky8891kq5s7jcpm1813h",
  manifest = (
    appTitle = (defaultText = "Sandpass"),
    appVersion = 5,  # Increment this for every release.
    appMarketingVersion = (defaultText = "1.1.0"),

    actions = [
      ( title = (defaultText = "New database"),
        nounPhrase = (defaultText = "database"),
        command = .launcher
      )
    ],
    continueCommand = .launcher,

    metadata = (
      icons = (
        appGrid = (svg = embed "icons/appGrid.svg"),
        grain = (svg = embed "icons/grain.svg"),
        market = (svg = embed "icons/market.svg"),
      ),

      website = "https://github.com/zombiezen/sandpass",
      codeUrl = "https://github.com/zombiezen/sandpass",

      license = (openSource = apache2,
                 notices = (defaultText = embed ".sandstorm/notices.txt")),

      categories = [productivity],

      author = (
        contactEmail = "ross@zombiezen.com",

        pgpSignature = embed ".sandstorm/pgp-signature",
      ),

      pgpKeyring = embed ".sandstorm/pgp-keyring",

      description = (defaultText = embed ".sandstorm/description.md"),
      shortDescription = (defaultText = "Password manager"),

      screenshots = [
        (width = 698, height = 704, png = embed ".sandstorm/screenshot-list.png"),
        (width = 791, height = 704, png = embed ".sandstorm/screenshot-edit.png"),
      ],
      changeLog = (defaultText = embed "CHANGELOG.md"),
    ),
  ),

  bridgeConfig = (
    viewInfo = (
      permissions = [
        ( name = "read",
          title = (defaultText = "Read from database"),
          obsolete = true,  # implied by sharing
        ),
        ( name = "write",
          title = (defaultText = "Make changes to database"),
        ),
        ( name = "init",
          title = (defaultText = "Create, delete, and rekey the database"),
        ),
      ],
      roles = [
        ( title = (defaultText = "viewer"),
          verbPhrase = (defaultText = "can read"),
          permissions = [true, false, false],
        ),
        ( title = (defaultText = "editor"),
          verbPhrase = (defaultText = "can read and write"),
          permissions = [true, true, false],
        ),
        ( title = (defaultText = "manager"),
          verbPhrase = (defaultText = "can read, write, and manage"),
          description = (defaultText = "A manager can not only edit the database, but also delete it."),
          permissions = [true, true, true],
        )
      ]
    )
  )
);

const launcher :Spk.Manifest.Command = (
  argv = [
    "/sandstorm-http-bridge", "8080", "--",
    "/opt/app/sandpass",
    "-listen=[::]:8080",
    "-db=/var/keepass.kdb",
    "-session_key=/var/session_key.json",
    "-static_dir=/opt/app",
    "-templates_dir=/opt/app/templates"
  ],
  environ = [
    (key = "PATH", value = "/usr/local/bin:/usr/bin:/bin"),
    (key = "SANDSTORM", value = "1"),
  ]
);
