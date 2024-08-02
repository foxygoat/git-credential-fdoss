// cmd git-credential-fdoss is a git credentials helper that uses the
// freedesktop.org secret service for storing and retrieving git credentials.
package main

import (
	"github.com/alecthomas/kong"
)

var version string = "v0.0.0"

const description = `
git-credential-fdoss manages your git credentials using the freedesktop.org
Secret Service.
`

type CLI struct {
	Version kong.VersionFlag `short:"V" help:"Print program version"`
}

func main() {
	cli := &CLI{}
	kctx := kong.Parse(cli,
		kong.Description(description),
		kong.Vars{"version": version},
	)
	err := kctx.Run(cli)
	kctx.FatalIfErrorf(err)
}
