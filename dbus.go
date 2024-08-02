package main

import (
	"fmt"
	"os"

	"github.com/godbus/dbus/v5"
)

// SecretService implements the freedesktop.org Secret Service API as needed
// for git-credential-fdoss to do what it needs to do. It is not a full
// implementation of the API.
//
// https://specifications.freedesktop.org/secret-service/latest
type SecretService struct {
	conn    *dbus.Conn
	svc     dbus.BusObject
	session dbus.BusObject
}

type Secret struct {
	Session     dbus.ObjectPath
	Params      []byte
	Secret      []byte
	ContentType string
}

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

func (ss *SecretService) Close() error {
	call := ss.session.Call("org.freedesktop.Secret.Session.Close", 0)
	return call.Err
}

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

func (ss *SecretService) search(attrs map[string]string) (unlocked, locked []dbus.ObjectPath, err error) {
	svc := ss.conn.Object("org.freedesktop.secrets", dbus.ObjectPath("/org/freedesktop/secrets"))
	call := svc.Call("org.freedesktop.Secret.Service.SearchItems", 0, attrs)
	err = call.Store(&unlocked, &locked)
	return
}

func (ss *SecretService) getSecret(itemPath dbus.ObjectPath) (secret Secret, err error) {
	item := ss.conn.Object("org.freedesktop.secrets", itemPath)
	call := item.Call("org.freedesktop.Secret.Item.GetSecret", 0, ss.session.Path())
	err = call.Store(&secret)
	return
}
