//nolint:err113 // dynamic errors in main are OK
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
				gc.Port = uint16(i)
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

func (gc *GitCredential) Marshal(w io.Writer) error {
	var err error
	marshal := func(k, v string) {
		if err != nil {
			return
		}
		if v == "" {
			return
		}
		_, err = fmt.Fprintf(w, "%s=%s\n", k, v)
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
