@0xba54be93d5898b97;

using Spk = import "/sandstorm/package.capnp";

const pkgdef :Spk.PackageDefinition = (
  # The package definition. Note that the spk tool looks specifically for the
  # "pkgdef" constant.

  id = "rq41p170hcs5rzg66axggv8r90fjcssdky8891kq5s7jcpm1813h",
  manifest = (
    appTitle = (defaultText = "Sandpass"),
    appVersion = 0,  # Increment this for every release.
    appMarketingVersion = (defaultText = "0.1.0"),

    actions = [
      ( title = (defaultText = "New database"),
        nounPhrase = (defaultText = "database"),
        command = .launcher
      )
    ],
    continueCommand = .launcher,

    metadata = (
      icons = (
        # Various icons to represent the app in various contexts.
        #appGrid = (svg = embed "path/to/appgrid-128x128.svg"),
        #grain = (svg = embed "path/to/grain-24x24.svg"),
        #market = (svg = embed "path/to/market-150x150.svg"),
        #marketBig = (svg = embed "path/to/market-big-300x300.svg"),
      ),

      website = "https://github.com/zombiezen/sandpass",
      codeUrl = "https://github.com/zombiezen/sandpass",

      license = (openSource = apache2,
                 notices = (defaultText = embed "notices.txt")),

      categories = [productivity],

      author = (
        contactEmail = "ross@zombiezen.com",

        pgpSignature = embed "pgp-signature",
      ),

      pgpKeyring = embed "pgp-keyring",

      #description = (defaultText = embed "path/to/description.md"),
      # The app's description in Github-flavored Markdown format, to be displayed e.g.
      # in an app store. Note that the Markdown is not permitted to contain HTML nor image tags (but
      # you can include a list of screenshots separately).

      shortDescription = (defaultText = "Password manager"),

      screenshots = [
        # Screenshots to use for marketing purposes.  Examples below.
        # Sizes are given in device-independent pixels, so if you took these
        # screenshots on a Retina-style high DPI screen, divide each dimension by two.

        #(width = 746, height = 795, jpeg = embed "path/to/screenshot-1.jpeg"),
        #(width = 640, height = 480, png = embed "path/to/screenshot-2.png"),
      ],
      #changeLog = (defaultText = embed "path/to/sandstorm-specific/changelog.md"),
      # Documents the history of changes in Github-flavored markdown format (with the same restrictions
      # as govern `description`). We recommend formatting this with an H1 heading for each version
      # followed by a bullet list of changes.
    ),
  ),

  sourceMap = (
    searchPath = [
      ( sourcePath = "." ),  # Search this directory first.
      ( sourcePath = "/",    # Then search the system root directory.
        hidePaths = [ "home", "proc", "sys",
                      "etc/passwd", "etc/hosts", "etc/host.conf",
                      "etc/nsswitch.conf", "etc/resolv.conf",
                      "etc/ld.so.cache" ]
      )
    ]
  ),

  fileList = "sandstorm-files.list",

  alwaysInclude = [
    "opt/app/sandpass",
    "opt/app/templates",
  ],

  bridgeConfig = (
    viewInfo = (
      permissions = [
        ( name = "read",
          title = (defaultText = "Read from database")
        ),
        ( name = "write",
          title = (defaultText = "Write to database")
        )
      ],
      roles = [
        ( title = (defaultText = "viewer"),
          verbPhrase = (defaultText = "can read"),
          permissions = [true, false]
        ),
        ( title = (defaultText = "editor"),
          verbPhrase = (defaultText = "can read and write"),
          permissions = [true, true]
        )
      ]
    )
  )
);

const launcher :Spk.Manifest.Command = (
  argv = ["/sandstorm-http-bridge", "8000", "--", "/opt/app/.sandstorm/launcher.sh"],
  environ = [
    (key = "PATH", value = "/usr/local/bin:/usr/bin:/bin"),
    (key = "SANDSTORM", value = "1"),
  ]
);
