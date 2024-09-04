package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// GitCredential is a Go struct form of a credential used in the
// [git-credential] protocol. It can be unmarshal from an [io.Reader] and
// marshaled to an [io.Writer].
//
// The git-credential protocol is a simple line-based key/value pair text
// protocol. A simple example for storing a secret is:
//
//	protocol=https
//	host=example.com
//	username=bob
//	password=secr3t
//
// A similar input without the "password" field would be used to retrieve a
// secret.
//
// [git-credential]: https://git-scm.com/docs/git-credential#IOFMT
type GitCredential struct {
	Protocol          string
	Host              string
	Port              uint16
	Path              string
	Username          string
	Password          string
	PasswordExpiryUTC string
	OauthRefreshToken string
	URL               string
	WWWAuth           []string
}

// Unmarshal reads a git credential in git-credential wire format into the
// GitCredential receiver. The "host" on the wire has the port split off if
// there is one there. If there is not, the Port field will contain 0. Other
// than that, no fields are interpreted as anything other than a string. This
// is largely as a git-credential helper does not need to concern itself with
// the content of the message (i.e. the "password_expiry_utc" field does not
// need to be interpreted as a date to store or retrieve credentials).
//
// Any unknown fields are ignored.
//
// If there are no errors, nil is returned. If an input line cannot be
// processed, an error is returned.
//
// Unmarshal will stop reading from the given io.Reader if it encounters an
// error on a line, a blank line is read, or EOF is reached.
func (gc *GitCredential) Unmarshal(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	// Scan until EOF or a blank line
	for scanner.Scan() && scanner.Text() != "" {
		k, v, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			return fmt.Errorf("malformed input line: missing '=': %s", scanner.Text())
		}
		switch k {
		case "protocol":
			gc.Protocol = v
		case "host":
			h, p, err := net.SplitHostPort(v)
			var ae *net.AddrError
			if errors.As(err, &ae) && ae.Err == "missing port in address" {
				gc.Host = v
				continue
			}
			if err != nil {
				return err
			}
			gc.Host = h
			if p != "" {
				i, err := strconv.ParseUint(p, 10, 16)
				if err != nil {
					return err
				}
				gc.Port = uint16(i) //nolint:gosec // not an integer overlflow
			}
		case "path":
			gc.Path = v
		case "username":
			gc.Username = v
		case "password":
			gc.Password = v
		case "password_expiry_utc":
			gc.PasswordExpiryUTC = v
		case "oauth_refresh_token":
			gc.OauthRefreshToken = v
		case "url":
			gc.URL = v
		case "wwwauth[]":
			if v == "" {
				gc.WWWAuth = nil
			} else {
				gc.WWWAuth = append(gc.WWWAuth, v)
			}
		default:
			// Ignore unknown fields for forward compatibility
		}
	}
	return nil
}

// Marshal writes the contents of the GitCredential receiver to the given
// io.Writer in git-credential wire format. Any empty fields of the receiver
// are ignored, as is a zero Port.
//
// If there is a error writing to the io.Writer, no further fields are written
// and the error is returned. If there is no error, nil is returned.
func (gc *GitCredential) Marshal(w io.Writer) error {
	var err error
	marshal := func(k, v string) {
		if err == nil && v != "" {
			_, err = fmt.Fprintf(w, "%s=%s\n", k, v)
		}
	}
	marshal("protocol", gc.Protocol)
	marshal("host", gc.Host)
	marshal("path", gc.Path)
	marshal("username", gc.Username)
	marshal("password", gc.Password)
	marshal("password_expiry_utc", gc.PasswordExpiryUTC)
	marshal("oauth_refresh_token", gc.OauthRefreshToken)
	marshal("url", gc.URL)
	for _, v := range gc.WWWAuth {
		marshal("wwwauth[]", v)
	}
	return err
}
