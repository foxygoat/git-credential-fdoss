package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/godbus/dbus/v5"
)

// SecretService implements a client of the freedesktop.org DBus [Secret
// Service Specification] implementing only the functionality needed for an
// implementation of a git credential helper. It is not a full client
// implementation of the DBus API.
//
// It supports adding secrets, looking them up and deleting them, mapping to
// the "store", "get" and "erase" commands of the git-credential protocol.
//
// [Secret Service Specification]: https://specifications.freedesktop.org/secret-service-spec/latest
type SecretService struct {
	conn    *dbus.Conn
	svc     dbus.BusObject
	session dbus.BusObject
}

// Secret is a struct compatible with the [Secret] struct type as defined in
// the specification. This Go struct uses types that are marshalable by the
// dbus library into the correct wire format - no struct tags or other magic
// needed.
//
// [Secret]: https://specifications.freedesktop.org/secret-service-spec/latest/types.html#type-Secret
type Secret struct {
	Session     dbus.ObjectPath
	Params      []byte
	Secret      []byte
	ContentType string
}

// NewSecretService constructs and returns a SecretService for acting as a
// client on the DBus session bus to the Secret Service. It establishes a
// [session] with the secret service. The session is configured only with
// "plain" encryption currently (i.e. no encryption). Encrypted sessions are
// still to be implemented.
//
// If the connection to DBus could not be established or if the secret service
// session could not be created, an error is returned instead.
//
// [session]: https://specifications.freedesktop.org/secret-service-spec/0.2/sessions.html
func NewSecretService() (*SecretService, error) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return nil, fmt.Errorf("couldn't connect to session bus: %w", err)
	}
	svc := conn.Object("org.freedesktop.secrets", dbus.ObjectPath("/org/freedesktop/secrets"))

	var path dbus.ObjectPath
	var output dbus.Variant
	call := svc.Call("org.freedesktop.Secret.Service.OpenSession", 0, "plain", dbus.MakeVariant(""))
	if err := call.Store(&output, &path); err != nil {
		return nil, fmt.Errorf("couldn't open secret session: %w", err)
	}

	session := conn.Object("org.freedesktop.secrets", path)

	return &SecretService{
		conn:    conn,
		svc:     svc,
		session: session,
	}, nil
}

// Close closes the session with the secret service, making it no longer
// possible to deal with secret data with the service. It is not necessary to
// close the session as the secret service will be notified when the client
// disconnects from the bus.
func (ss *SecretService) Close() error {
	call := ss.session.Call("org.freedesktop.Secret.Session.Close", 0)
	return call.Err
}

// Get looks up [items] in the default [collection] by the given set of
// attributes and returns the secret of the first item that matches those
// attributes. If there are no matches, an empty string is returned, signifying
// no password was found.
//
// The attributes are a set of arbitrary name/value strings that were provided
// when the secret was stored.
//
// Only secrets that match on all attributes and have no extra attributes are
// considered. If there are multiple exact matches, the first is returned. It
// is not clear what the ordering of the secrets is, so the "first" secret may
// be arbitrary. However, it should not be possible to have multiple secrets
// with the same attribues so this should not happen.
//
// Currently only unlocked secrets can be returned. If only a locked secret
// matches the attributes, a diagnostic error will be printed to stderr and no
// secret will be returned.
//
// If an error looking up the items identified by the attributes occurs or an
// error returning the secret for the selected item occurs, an empty string is
// returned.
//
// See makeAttrs() for the attributes used by git-credential-fdoss.
//
// [items]: https://specifications.freedesktop.org/secret-service-spec/0.2/ch03.html
// [collection]: https://specifications.freedesktop.org/secret-service-spec/0.2/ch03.html
func (ss *SecretService) Get(attrs map[string]string) (string, error) {
	unlocked, locked, err := ss.search(attrs)
	if err != nil {
		return "", err
	}

	// Find the first item with an exact attribute match. Sometimes
	// attrs may be a subset of attributes that have been stored (e.g.
	// may not contain a path), and we want to skip those. We return
	// the secret of the first one found that matches.
	for _, item := range unlocked {
		ok, err := ss.attrsMatch(attrs, item)
		if err != nil {
			// We could continue to the next item but errors
			// should not happen here, so lets surface them early.
			return "", err
		}
		if !ok {
			continue
		}
		secret, err := ss.getSecret(item)
		if err != nil {
			return "", err
		}
		return string(secret.Secret), nil
	}

	if len(locked) > 0 {
		fmt.Fprintln(os.Stderr, "TODO: Found locked secret. Sorry, can't unlock yet")
	}

	return "", nil
}

// Store stores a secret with the secret service using the given descriptive
// label, a set of key/value string attributes for looking up the secret and
// the actual secret value. The secret is stored in the default collection. If
// the secret could not be created, an error is returned.
func (ss *SecretService) Store(label string, attrs map[string]string, secret string) error {
	path := dbus.ObjectPath("/org/freedesktop/secrets/aliases/default")
	collection := ss.conn.Object("org.freedesktop.secrets", path)
	props := map[string]dbus.Variant{
		"org.freedesktop.Secret.Item.Label":      dbus.MakeVariant(label),
		"org.freedesktop.Secret.Item.Attributes": dbus.MakeVariant(attrs),
	}
	sec := Secret{
		Session:     ss.session.Path(),
		Secret:      []byte(secret),
		ContentType: "text/plain",
	}

	var itemPath, promptPath dbus.ObjectPath
	call := collection.Call("org.freedesktop.Secret.Collection.CreateItem", 0, props, &sec, true)
	if err := call.Store(&itemPath, &promptPath); err != nil {
		return fmt.Errorf("couldn't create secret: %w", err)
	}
	return nil
}

// Delete removes a secret matching the given attributes. If expectedPassword
// is not empty, then the secret matching the attributes will only be removed
// if the password in the value of the secret stored matches expectedPassword.
// If expectedPassword is empty, then the secret will be removed if it just
// matches the attributes.
//
// Only secrets that match on all attributes and have no extra attributes are
// considered. If there are multiple exact matches, the first is returned. It
// is not clear what the ordering of the secrets is, so the "first" secret may
// be arbitrary. However, it should not be possible to have multiple secrets
// with the same attribues so this should not happen.
//
// Currently only unlocked secrets can be deleted. If only a locked secret
// matches the attributes, a diagnostic error will be printed to stderr and no
// secret will be deleted.
//
// If an error looking up the items occurs, an error returning the secret for
// the selected item occurs, or the secret cannot be deleted, an error is
// returned.
func (ss *SecretService) Delete(attrs map[string]string, expectedPassword string) error {
	unlocked, locked, err := ss.search(attrs)
	if err != nil {
		return err
	}

	// Find the first item with an exact attribute match. Sometimes
	// attrs may be a subset of attributes that have been stored (e.g.
	// may not contain a path), and we want to skip those. Ensure that
	// expectedSecret matches the stored secret value
	// the secret of the first one found that matches.
	var itemPath dbus.ObjectPath
	for _, item := range unlocked {
		ok, err := ss.attrsMatch(attrs, item)
		if err != nil {
			// We could continue to the next item but errors
			// should not happen here, so lets surface them early.
			return err
		}
		if !ok {
			continue
		}
		// We will only erase the secret when presented with a password if the password
		// stored in the secret matches that password. A secret can contain multiple
		// fields separated by newlines. The password is the part before the first
		// newline if there is one at all.
		if expectedPassword != "" {
			secret, err := ss.getSecret(item)
			if err != nil {
				return err
			}
			password, _, _ := strings.Cut(string(secret.Secret), "\n")
			if password != expectedPassword {
				continue
			}
		}
		itemPath = item
		break
	}

	if !itemPath.IsValid() && len(locked) > 0 {
		fmt.Fprintln(os.Stderr, "TODO: Found locked secret. Sorry, can't unlock for erase yet")
	}
	if !itemPath.IsValid() {
		return nil
	}

	item := ss.conn.Object("org.freedesktop.secrets", itemPath)
	call := item.Call("org.freedesktop.Secret.Item.Delete", 0)
	var promptPath dbus.ObjectPath
	if err := call.Store(&promptPath); err != nil {
		return err
	}

	if promptPath != dbus.ObjectPath("/") {
		fmt.Fprintln(os.Stderr, "TODO: Got prompt on delete. Sorry, can't do that yet")
	}

	return nil
}

// search returns all the unlocked and locked secret items that match the given
// attributes. If the DBus call fails, an error is returned.
func (ss *SecretService) search(attrs map[string]string) (unlocked, locked []dbus.ObjectPath, err error) {
	svc := ss.conn.Object("org.freedesktop.secrets", dbus.ObjectPath("/org/freedesktop/secrets"))
	call := svc.Call("org.freedesktop.Secret.Service.SearchItems", 0, attrs)
	err = call.Store(&unlocked, &locked)
	return
}

// getSecret returns the secret struct for the given item path, or an error if
// the DBus call fails.
func (ss *SecretService) getSecret(itemPath dbus.ObjectPath) (secret Secret, err error) {
	item := ss.conn.Object("org.freedesktop.secrets", itemPath)
	call := item.Call("org.freedesktop.Secret.Item.GetSecret", 0, ss.session.Path())
	err = call.Store(&secret)
	return
}

// attrsMatch returns true if the given items have exactly the given
// attributes. If the item has extra or fewer attributes, or any values are
// different, false is returned. If the attributes of the item could be
// retrieved an error is returned.
func (ss *SecretService) attrsMatch(attrs map[string]string, itemPath dbus.ObjectPath) (bool, error) {
	item := ss.conn.Object("org.freedesktop.secrets", itemPath)
	prop, err := item.GetProperty("org.freedesktop.Secret.Item.Attributes")
	if err != nil {
		return false, err
	}

	itemAttrs, ok := prop.Value().(map[string]string)
	if !ok {
		return false, fmt.Errorf("item attributes property is not a map: %v", itemPath)
	}

	if len(itemAttrs) != len(attrs) {
		return false, nil
	}
	for k, v1 := range attrs {
		v2, ok := itemAttrs[k]
		if !ok || v1 != v2 {
			return false, nil
		}
	}
	return true, nil
}
