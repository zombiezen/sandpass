# Sandpass Changelog

## Unreleased

## v1.1.0

### Added
- Attachments! Sandpass now allows you to add and remove files from entries.
  ([#13][])

[#13]: https://github.com/zombiezen/sandpass/issues/13

### Changed
- Sessions are now persistent across grain restarts ([#31][]). This means less
  master password typing for long sessions.
- The passphrase generator word list has changed and is now vendored.
- Builds are now using Go modules and [docker-spk][].

[#31]: https://github.com/zombiezen/sandpass/issues/31
[docker-spk]: https://github.com/zenhack/docker-spk

### Fixed
- Address potential database data loss issue ([#23][])
- Fix bold font rendering issue on ChromeOS.
- Updated Go libraries.

[#23]: https://github.com/zombiezen/sandpass/issues/23

## v1.0.0

* New new icons (thanks again, @neynah. You rock.)
* Search
  * Multi-word searches match individual words instead of literal phrases
  * Searches happen over entry notes, not just titles
  * Show entry's group in results page
* Security Precautions
  * Pages are marked as uncacheable to avoid the user agent potentially storing
    credentials in clear text
  * Disabled autocomplete on entry form fields for similar reasons.
  * Added basic XSRF protection.  Defense in depth here, as Sandstorm protects
    against XSRF attacks anyway.
* Minor visual tweaks

## v1.0.0-rc1

* Features
  * Search (#3)
  * Password generation (#11)
  * Deletion of entries (#5)
  * Deletion of entire database (#8)
  * Moving entities and groups between groups (#15)
  * Creating, editing, and deleting groups (#4)
  * Separate out management role (#18)
* Bug Fixes
  * Preserve attachments in existing KeePass databases (#12)
  * Clear sessions from memory shortly after expiring (#14)

## v0.2.2

* New icon (thanks @neynah)
* Store derived key in sessions instead of password/keyfile (improves request
  performance)
* Security: generate random IV for every write

## v0.2.1

* Basic styling
* Actually bump version number

## v0.2.0

* Allow toggling password visibility
* Direct copy of passwords
* Bypass credentials page if database is not encrypted
* Add breadcrumb navigation
* Update Sandstorm shell paths and titles on page navigation

## v0.1.0

Initial public release.
