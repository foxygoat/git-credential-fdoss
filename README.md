# git-credential-fdoss

`git-credential-fdoss` is a [git credential helper] that uses the
[freedesktop.org Secret Service] via [D-Bus] for storage of git credentials.

[git credential helper]: https://git-scm.com/doc/credential-helpers
[freedesktop.org Secret Service]: https://specifications.freedesktop.org/secret-service/
[D-Bus]: https://www.freedesktop.org/wiki/Software/dbus/

    go install foxygo.at/git-credential-helper@latest

This credential helper fulfils the same role as `git-credential-libsecret` but
is intended to be easier to install and be more portable as a binary.
`git-credential-libsecret` is mostly distributed as source code as a
contribution to `git`. A binary build has dependencies on a number of GNOME
desktop libraries which may not be present on a target machine.
