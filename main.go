// cmd git-credential-fdoss is a git credentials helper that uses the
// freedesktop.org secret service for storing and retrieving git credentials.
//
//nolint:err113 // dynamic errors in main are OK
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
	// This close is not strictly necessary as the session is close automatically
	// when the caller goes away, but it is here to capture errors more for
	// debugging and understanding.
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

func (cmd *CmdStore) AfterApply(gc *GitCredential) error {
	cmd.validate(gc.Protocol != "", "protocol")
	cmd.validate(gc.Username != "", "username")
	cmd.validate(gc.Password != "", "password")
	cmd.validate(gc.Host != "" || gc.Path != "", "host or path")
	return cmd.err
}

func (cmd *CmdStore) Run(gc *GitCredential, ss *SecretService) error {
	return ss.Store(makeLabel(gc), makeAttrs(gc), makeSecretVal(gc))
}

func (cmd *CmdErase) AfterApply(gc *GitCredential) error {
	cmd.validate(gc.Protocol != "", "protocol")
	cmd.validate(gc.Username != "", "username")
	cmd.validate(gc.Host != "", "host")
	cmd.validate(gc.Path != "", "path")
	return cmd.err
}

func (cmd *CmdErase) Run(gc *GitCredential, ss *SecretService) error {
	return ss.Delete(makeAttrs(gc), makeSecretVal(gc))
}

func makeLabel(gc *GitCredential) string {
	label := "Git: " + gc.Protocol + "://" + gc.Host
	if gc.Port != 0 {
		label += ":" + strconv.FormatUint(uint64(gc.Port), 10)
	}
	label += "/" + gc.Path
	return label
}

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

func makeSecretVal(gc *GitCredential) string {
	secret := gc.Password
	if gc.PasswordExpiryUTC != "" {
		secret += "\npassword_expiry_utc=" + gc.PasswordExpiryUTC
	}
	if gc.OauthRefreshToken != "" {
		secret += "\noauth_refresh_token=" + gc.OauthRefreshToken
	}
	return secret
}

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
