// cmd git-credential-fdoss is a git credentials helper that uses the
// freedesktop.org secret service for storing and retrieving git credentials.
//
//	Usage: git-credential-fdoss <command> [flags]
//
//	git-credential-fdoss manages your git credentials using the freedesktop.org
//	Secret Service.
//
//	Flags:
//	  -h, --help       Show context-sensitive help.
//	  -V, --version    Print program version
//
//	Commands:
//	  get [flags]
//	    Get credentials from keyring
//
//	  store [flags]
//	    Save credentials to keyring
//
//	  erase [flags]
//	    Erase credentials from keyring
//
//	Run "git-credential-fdoss <command> --help" for more information on a command.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/alecthomas/kong"
)

var version string = "v0.0.0"

const description = `
git-credential-fdoss manages your git credentials using the freedesktop.org
Secret Service.
`

type CLI struct {
	Get   CmdGet   `cmd:"" help:"Get credentials from keyring"`
	Store CmdStore `cmd:"" help:"Save credentials to keyring"`
	Erase CmdErase `cmd:"" help:"Erase credentials from keyring"`

	Version kong.VersionFlag `short:"V" help:"Print program version"`
}

type validator struct{ err error }

type (
	CmdGet   struct{ validator }
	CmdStore struct{ validator }
	CmdErase struct{ validator }
)

func main() {
	cli := &CLI{}
	kctx := kong.Parse(cli,
		kong.Description(description),
		kong.Vars{"version": version},
	)
	err := kctx.Run(cli)
	kctx.FatalIfErrorf(err)
}

// validate is a helper function to simplify validing input fields for the
// CLI commands. It saves the first error encountered, and is a no-op for
// calls after the first error is recorded.
func (v *validator) validate(ok bool, errmsg string) {
	if v.err != nil {
		return
	}
	if !ok {
		v.err = fmt.Errorf("input field %s must be set", errmsg)
	}
}

// Run cleans up after a command. It is called after any commands are run.
func (cmd *CLI) Run(ss *SecretService) error {
	// This close is not strictly necessary as the session is closed
	// automatically when the caller goes away, but it is here to capture
	// errors for debugging and understanding.
	return ss.Close()
}

// AfterApply on CLI runs before AfterApply of any commands, creating a
// GitCredential from stdin and opening a connection to DBus and creating
// a session with the secret service. These two resources are bound to
// the kong context to make them available to the command Run methods.
func (cmd *CLI) AfterApply(kctx *kong.Context) error {
	// Create a GitCredential from the lines on stdin. See
	// git-credential(1) for the format.
	// https://git-scm.com/docs/git-credential#IOFMT
	gc := &GitCredential{}
	if err := gc.Unmarshal(os.Stdin); err != nil {
		return err
	}
	kctx.Bind(gc)

	// Open a DBus connection and create a session with the secret service.
	// https://specifications.freedesktop.org/secret-service/latest/
	ss, err := NewSecretService()
	if err != nil {
		return err
	}
	kctx.Bind(ss)

	return nil
}

// AfterApply validates the input credential fields for a get command.
func (cmd *CmdGet) AfterApply(gc *GitCredential) error {
	cmd.validate(gc.Protocol != "", "protocol")
	cmd.validate(gc.Host != "" || gc.Path != "", "host or path")
	return cmd.err
}

// Run executes the credential helper "get" operation.
//
// The "get" operation is specified by the [gitcredentials] documentation, and
// exists to look up a password and/or other secret material to access a remote
// git repository, previously stored with a "store" operation.
//
// [gitcredentials]: https://git-scm.com/docs/gitcredentials
func (cmd *CmdGet) Run(gc *GitCredential, ss *SecretService) error {
	secret, err := ss.Get(makeAttrs(gc))
	if err != nil {
		return err
	}

	if secret == "" {
		return nil
	}

	if err := parseSecretVal(secret, gc); err != nil {
		return err
	}

	return gc.Marshal(os.Stdout)
}

// AfterApply validates the input credential fields for a store command.
func (cmd *CmdStore) AfterApply(gc *GitCredential) error {
	cmd.validate(gc.Protocol != "", "protocol")
	cmd.validate(gc.Username != "", "username")
	cmd.validate(gc.Password != "", "password")
	cmd.validate(gc.Host != "" || gc.Path != "", "host or path")
	return cmd.err
}

// Run executes the credential helper "store" operation.
//
// The "store" operation is specified by the [gitcredentials] documentation,
// and exists to store a password and/or other secret material needed to access
// a remote git repository.
//
// [gitcredentials]: https://git-scm.com/docs/gitcredentials
func (cmd *CmdStore) Run(gc *GitCredential, ss *SecretService) error {
	return ss.Store(makeLabel(gc), makeAttrs(gc), formatSecretVal(gc))
}

// AfterApply validates the input credential fields for a erase command.
func (cmd *CmdErase) AfterApply(gc *GitCredential) error {
	cmd.validate(gc.Protocol != "", "protocol")
	cmd.validate(gc.Username != "", "username")
	cmd.validate(gc.Host != "" || gc.Path != "", "host or path")
	return cmd.err
}

// Run executes the credential helper "erase" operation.
//
// The "erase" operation is specified by the [gitcredentials] documentation,
// and exists to delete a password and/or other secret material previously
// stored with a "store" operation.
//
// [gitcredentials]: https://git-scm.com/docs/gitcredentials
func (cmd *CmdErase) Run(gc *GitCredential, ss *SecretService) error {
	return ss.Delete(makeAttrs(gc), gc.Password)
}

// makeLabel returns a string describing the given GitCredential, used as a
// descriptive label for a secret stored with the secret service. The label
// is the same as created by git-credential-libsecret, although that is not
// required for compatibility.
func makeLabel(gc *GitCredential) string {
	label := "Git: " + gc.Protocol + "://" + gc.Host
	if gc.Port != 0 {
		label += ":" + strconv.FormatUint(uint64(gc.Port), 10)
	}
	label += "/" + gc.Path
	return label
}

// makeAttrs maps the fields of GitCredentials to secret service attribues. The
// [mapping] is taken from git-credential-libsecret to be compatible with it.
//
// [mapping]: https://github.com/git/git/blob/159f2d50e75c17382c9f4eb7cbda671a6fa612d1/contrib/credential/libsecret/git-credential-libsecret.c#L90
func makeAttrs(gc *GitCredential) map[string]string {
	attrs := map[string]string{
		"xdg:schema": "org.git.Password",
	}
	if gc.Username != "" {
		attrs["user"] = gc.Username
	}
	if gc.Protocol != "" {
		attrs["protocol"] = gc.Protocol
	}
	if gc.Host != "" {
		attrs["server"] = gc.Host
	}
	if gc.Port != 0 {
		attrs["port"] = strconv.FormatUint(uint64(gc.Port), 10)
	}
	if gc.Path != "" {
		attrs["object"] = gc.Path
	}
	return attrs
}

// formatSecretVal encodes the secret and/or variable parts of a GitCredential
// into a string suitable for storing with the secret service. Variable parts,
// such as the password expiry time, cannot be encoded as an attribute as they
// need to match on lookup.
//
// The format for [encoding] multiple values is the same as used by
// git-credential-libsecret to be compatible with it.
//
// Note: This encoding is not compatible with the unencrypted keyring format of
// gnome-keyring. Gnome-keyring does not escape the newlines in secrets when
// storing them in an unencrypted keyring, and those newlines appear as field
// separators in the keyring. When the secret is read back, it is only read
// back to the first newline, so we don't get back all that we stored.
//
// It would not be typical to be using unencrypted keyrings though as it mostly
// defeats the purpose of a secret manager. If one did not care about
// unencrypted storage of git credentials, git-credential-store (bundled with
// git) would make more sense than this credential helper.
//
// [encoding]: https://github.com/git/git/blob/159f2d50e75c17382c9f4eb7cbda671a6fa612d1/contrib/credential/libsecret/git-credential-libsecret.c#L212
func formatSecretVal(gc *GitCredential) string {
	secret := gc.Password
	if gc.PasswordExpiryUTC != "" {
		secret += "\npassword_expiry_utc=" + gc.PasswordExpiryUTC
	}
	if gc.OauthRefreshToken != "" {
		secret += "\noauth_refresh_token=" + gc.OauthRefreshToken
	}
	return secret
}

// parseSecretVal extracts the fields encoded in a secret string into the given
// GitCredential. Unknown fields are ignored. An error is returned if there are
// any malformed fields that could not be extracted.
func parseSecretVal(secret string, gc *GitCredential) error {
	scanner := bufio.NewScanner(strings.NewReader("password=" + secret))
	for scanner.Scan() {
		k, v, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			return errors.New("malformed secret returned from secret service (missing '=')")
		}
		switch k {
		case "password":
			gc.Password = v
		case "password_expiry_utc":
			gc.PasswordExpiryUTC = v
		case "oauth_refresh_token":
			gc.OauthRefreshToken = v
		default:
			// Ignore unknown fields for forward compatibiilty
		}
	}
	return nil
}
