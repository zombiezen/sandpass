# v1.0.0-rc1

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

# v0.2.2

* New icon (thanks @neynah)
* Store derived key in sessions instead of password/keyfile (improves request
  performance)
* Security: generate random IV for every write

# v0.2.1

* Basic styling
* Actually bump version number

# v0.2.0

* Allow toggling password visibility
* Direct copy of passwords
* Bypass credentials page if database is not encrypted
* Add breadcrumb navigation
* Update Sandstorm shell paths and titles on page navigation

# v0.1.0

Initial public release.
