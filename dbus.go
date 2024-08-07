package main

import (
	"fmt"
	"os"

	"github.com/godbus/dbus/v5"
)

// SecretService implements a client of the freedesktop.org DBus [Secret
// Service Specification] as needed for git-credential-fdoss to do what it
// needs to do. It is not a full implementation of the API.
//
// It supports adding secrets, looking them up and deleting them, mapping to
// the "store", "get" and "erase" commands of the git-credential protocol.
//
// [Secret Service Specification]: // https://specifications.freedesktop.org/secret-service-spec/latest
type SecretService struct {
	conn    *dbus.Conn
	svc     dbus.BusObject
	session dbus.BusObject
}

// Secret is a struct compatible with the [Secret] struct type as defined in
// the specification. This Go struct is marshalable by the dbus library into
// the correct wire format.
//
// [Secret]: // https://specifications.freedesktop.org/secret-service-spec/latest/types.html#type-Secret
type Secret struct {
	Session     dbus.ObjectPath
	Params      []byte
	Secret      []byte
	ContentType string
}

// NewSecretService constructs and returns a SecretService for acting as a
// client on the DBus session bus to the Secret Service. It establishes a
// session with the secret service, although currently only can configure
// "plain" encryption (i.e. no encryption).
//
// If the connection to DBus could not be established or the session could not
// be created, an error is retured instead.
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

// Get looks up a secret idenfied by the given set of attributes and returns
// the first secret that matches those attributes, or an empty string if there
// are no matching secrets. The attributes are a set of name/value arbitrary
// strings that were provided when the secret was stored.
//
// If more that one unlocked secret matches the attributes, a diagnostic error
// will be printed on stderr and the first matching secret will be returned. It
// is not clear what the ordering of the secrets is, so the "first" secret may
// be arbitrary.
//
// Currently only unlocked secrets can be returned. If only a locked secret
// matches the attributes, a diagnostic error will be printed to stderr and no
// secret will be returned.
//
// If an error looking up the items occurs or an error returning the secret for
// the selected item occurs, it is returned without a secret.
//
// See makeAttrs() for the attributes used by git-credential-fdoss.
func (ss *SecretService) Get(attrs map[string]string) (string, error) {
	unlocked, locked, err := ss.search(attrs)
	if err != nil {
		return "", err
	}

	switch {
	case len(unlocked) > 1:
		fmt.Fprintln(os.Stderr, "Warning: Got more than one secret back. Using only the first")
		fallthrough
	case len(unlocked) > 0:
		secret, err := ss.getSecret(unlocked[0])
		if err != nil {
			return "", err
		}
		return string(secret.Secret), nil
	case len(locked) > 0:
		fmt.Fprintln(os.Stderr, "TODO: Found locked secret. Sorry, can't unlock yet")
	default:
		// secret not found. return nothing
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

// Delete removes a secret matching the given attributes. If expectedSecret is
// not empty, then the secret matching the attributes will only be removed if
// the value of the secret stored matches expectedSecret. If expectedSecret is
// empty, then the secret will be removed if it just matches the attributes.
//
// If more that one unlocked secret matches the attributes, a diagnostic error
// will be printed on stderr and the first matching secret will be deleted. It
// is not clear what the ordering of the secrets is, so the "first" secret may
// be arbitrary.
//
// Currently only unlocked secrets can be deleted. If only a locked secret
// matches the attributes, a diagnostic error will be printed to stderr and no
// secret will be deleted.
//
// If an error looking up the items occurs, an error returning the secret for
// the selected item occurs, or the secret cannot be deleted, an error is
// returned.
func (ss *SecretService) Delete(attrs map[string]string, expectedSecret string) error {
	unlocked, locked, err := ss.search(attrs)
	if err != nil {
		return err
	}

	var itemPath dbus.ObjectPath
	switch {
	case len(unlocked) > 1:
		fmt.Fprintln(os.Stderr, "Warning: Got more than one secret back. Erasing only the first")
		fallthrough
	case expectedSecret != "" && len(unlocked) > 0:
		// We will only erase the secret when presented with a password if the password
		// stored in the secret matches that password.
		secret, err := ss.getSecret(unlocked[0])
		if err != nil {
			return err
		}
		if string(secret.Secret) == expectedSecret {
			itemPath = unlocked[0]
		}
	case len(locked) > 0:
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
// attrivutes. If the DBus call fails, an error is returned.
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
