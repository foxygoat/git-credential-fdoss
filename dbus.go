package main

import (
	"errors"
	"fmt"
	"iter"
	"math/big"
	"os"
	"strings"

	"github.com/godbus/dbus/v5"
)

const (
	noPrompt = dbus.ObjectPath("/")
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
	aesKey  []byte
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

	ss := &SecretService{
		conn: conn,
		svc:  svc,
	}

	if err := ss.OpenSession(); err != nil {
		return nil, err
	}

	return ss, nil
}

// OpenSession opens a [session] to the secret service. Upon opening a session,
// an AES key may be generated to secure the [transfer of secrets] with the
// Secret Service. If no AES key is generated (len(ss.aesKey) == 0), then
// secrets are not encrypted across the bus.
//
// We first try to negotiate an encrypted session, and if that fails we
// fallback to a plain session. Not all implementations of the Secret Service
// may support encrypted sessions.
//
// [session]: https://specifications.freedesktop.org/secret-service-spec/latest/sessions.html
// [transfer of secrets]: https://specifications.freedesktop.org/secret-service-spec/latest/transfer-secrets.html
func (ss *SecretService) OpenSession() error {
	sessionPath, err := ss.openDHSession()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Warning: Failed to open encrypted session. Falling back to unencrypted.")
		sessionPath, err = ss.openPlainSession()
		if err != nil {
			return err
		}
	}
	ss.session = ss.conn.Object("org.freedesktop.secrets", sessionPath)
	return nil
}

// openPlainSession opens a [plain] session to the secret service. Secets are
// not encrypted over the bus with a plain session. It returns the path to the
// session if successful, otherwise it returns an error.
//
// [plain]: https://specifications.freedesktop.org/secret-service-spec/latest/ch07s02.html
func (ss *SecretService) openPlainSession() (dbus.ObjectPath, error) {
	input := dbus.MakeVariant("")
	var output dbus.Variant
	var sessionPath dbus.ObjectPath
	call := ss.svc.Call("org.freedesktop.Secret.Service.OpenSession", 0, "plain", input)
	err := call.Store(&output, &sessionPath)
	return sessionPath, err
}

// openDHSession opens a [dh-ietf1024-sha256-aes128-cbc-pkcs7] session to the
// secret service. Secrets are encrypted using an AES key generated via a
// Diffie-Hellman exchange performed when opening the session. It returns the
// path to the session if successful, otherwise it returns an error.
//
// [dh-ietf1024-sha256-aes128-cbc-pkcs7]: https://specifications.freedesktop.org/secret-service-spec/latest/ch07s03.html
func (ss *SecretService) openDHSession() (dbus.ObjectPath, error) {
	group := rfc2409SecondOakleyGroup()
	private, public, err := group.NewKeypair()
	if err != nil {
		return "", err
	}

	input := dbus.MakeVariant(public.Bytes()) // math/big.Int.Bytes is big endian
	var output dbus.Variant
	var sessionPath dbus.ObjectPath
	call := ss.svc.Call("org.freedesktop.Secret.Service.OpenSession", 0, "dh-ietf1024-sha256-aes128-cbc-pkcs7", input)
	err = call.Store(&output, &sessionPath)
	if err != nil {
		return "", err
	}

	outputBytes, ok := output.Value().([]byte)
	if !ok {
		return "", fmt.Errorf("output type of OpenSession was not []bytes: %T", output.Value())
	}

	theirPublic := new(big.Int)
	theirPublic.SetBytes(outputBytes)
	ss.aesKey, err = group.keygenHKDFSHA256AES128(theirPublic, private)
	if err != nil {
		return "", err
	}
	return sessionPath, nil
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
	results, err := ss.searchExact(attrs)
	if err != nil {
		return "", err
	}

	for itemPath, err := range results {
		if err != nil {
			return "", err
		}
		secret, err := ss.getSecret(itemPath)
		if err != nil {
			return "", err
		}
		sec, err := ss.unmarshalSecret(&secret)
		if err != nil {
			return "", err
		}
		return sec, nil
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
	sec, err := ss.marshalSecret(secret)
	if err != nil {
		return err
	}

	// Try to unlock the collection first. Will be a no-op if it is not locked
	// but if it is locked, we'll prompt the user to unlock it.
	if _, err := ss.unlockObject(path); err != nil {
		return err
	}

	var itemPath, promptPath dbus.ObjectPath
	call := collection.Call("org.freedesktop.Secret.Collection.CreateItem", 0, props, &sec, true)
	if err := call.Store(&itemPath, &promptPath); err != nil {
		return fmt.Errorf("couldn't create secret: %w", err)
	}

	if promptPath != noPrompt {
		return ss.prompt(promptPath)
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
	results, err := ss.searchExact(attrs)
	if err != nil {
		return err
	}

	var itemPath dbus.ObjectPath
	for item, err := range results {
		if err != nil {
			return err
		}
		if expectedPassword != "" {
			secret, err := ss.getSecret(item)
			if err != nil {
				return err
			}
			sec, err := ss.unmarshalSecret(&secret)
			if err != nil {
				return err
			}
			password, _, _ := strings.Cut(sec, "\n")
			if password != expectedPassword {
				continue
			}
		}
		itemPath = item
		break
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

	if promptPath == noPrompt {
		return nil
	}

	return ss.prompt(promptPath)
}

// marshalSecret marshals the given secret into a Secret struct suitable for
// passing to the Secret Service for storage. If the receiver has an AES key,
// it is used to encrypt the secret as well as to populate the initialisation
// vector (IV) that is the parameter of the Secret. If the AES key in the
// receiver is empty, the secret is not encrypted. If there was an error
// encrypting the secret, it is returned.
func (ss *SecretService) marshalSecret(secret string) (*Secret, error) {
	sec := &Secret{
		Session:     ss.session.Path(),
		Secret:      []byte(secret),
		ContentType: "text/plain",
	}

	if len(ss.aesKey) > 0 {
		iv, ciphertext, err := unauthenticatedAESCBCEncrypt([]byte(secret), ss.aesKey)
		if err != nil {
			return nil, err
		}
		sec.Params = iv
		sec.Secret = ciphertext
	}
	return sec, nil
}

// unmarshalSecret unmarshals the secret from the Secret struct returned from
// the Secret Service and returns the string form of the secret. If the
// receiver has an AES key, it is used to decrypt the secret in the Secret
// struct using the Param as the initialisation vector (IV) to the AES
// decryper. If the AES key in the receiver is empty, the secret is not
// decrypted. If there was an error decrypting the secret, it is returned.
func (ss *SecretService) unmarshalSecret(secret *Secret) (string, error) {
	plaintext := secret.Secret
	if len(ss.aesKey) > 0 {
		var err error
		plaintext, err = unauthenticatedAESCBCDecrypt(secret.Params, secret.Secret, ss.aesKey)
		if err != nil {
			return "", err
		}
	}
	return string(plaintext), nil
}

// searchExact returns a function iterator that iterates all the items in the
// SecretService that exactly match the given attributes. This is a more strict
// search than the [SearchItems] method of the service in that the items
// returned by the iterator will have only the given attribute and no extras.
//
// The iterator returns the item object path as the key and an error if the
// item's attributes could not be retrieved.
//
// e.g.
//
//	results, err := ss.searchExact(attrs) {
//	if err != nil {
//		return err
//	}
//	for itemPath, err := results {
//		if err != nil {
//			return err
//		}
//		// .. do something with itemPath
//	}
//
// [SearchItems]: https://specifications.freedesktop.org/secret-service-spec/latest/org.freedesktop.Secret.Service.html#org.freedesktop.Secret.Service.SearchItems
func (ss *SecretService) searchExact(attrs map[string]string) (iter.Seq2[dbus.ObjectPath, error], error) {
	unlocked, locked, err := ss.search(attrs)
	if err != nil {
		return nil, err
	}
	f := func(yield func(item dbus.ObjectPath, err error) bool) {
		for _, itemPath := range unlocked {
			ok, err := ss.attrsMatch(attrs, itemPath)
			if !ok && err == nil {
				continue
			}
			if !yield(itemPath, err) {
				return
			}
		}
		for _, itemPath := range locked {
			ok, err := ss.attrsMatch(attrs, itemPath)
			if !ok && err == nil {
				continue
			}
			if err == nil {
				itemPath, err = ss.unlockObject(itemPath)
			}
			if !yield(itemPath, err) {
				return
			}
		}
	}
	return f, nil
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

func (ss *SecretService) unlockObject(itemPath dbus.ObjectPath) (dbus.ObjectPath, error) {
	unlocked, promptPath, err := ss.unlock([]dbus.ObjectPath{itemPath})
	if err != nil {
		return "", err
	}

	if len(unlocked) > 0 {
		// we'll never get back more than 1 item in the slice
		return unlocked[0], nil
	}

	if promptPath == noPrompt {
		return "", fmt.Errorf("huh? no item or prompt when unlocking: %v", itemPath)
	}

	if err := ss.prompt(promptPath); err != nil {
		return "", err
	}
	return itemPath, nil
}

// unlock attempts to [unlock] the objects given and returns the paths for the
// objects that were unlocked and a prompt path to unlock the remainder.
//
// [unlock]: https://specifications.freedesktop.org/secret-service-spec/latest/unlocking.html
func (ss *SecretService) unlock(objects []dbus.ObjectPath) (unlocked []dbus.ObjectPath, prompt dbus.ObjectPath, err error) {
	svc := ss.conn.Object("org.freedesktop.secrets", dbus.ObjectPath("/org/freedesktop/secrets"))
	call := svc.Call("org.freedesktop.Secret.Service.Unlock", 0, objects)
	err = call.Store(&unlocked, &prompt)
	return
}

// prompt calls Prompt on the [prompt] object at the given path and waits for
// the Completed signal to be emitted from it. It returns true if the prompt
// was completed, or false if it was cancelled. If an error occurs subscribing
// to the signal or calling the prompt object, it is returned instead.
//
// [prompt]: https://specifications.freedesktop.org/secret-service-spec/latest/prompts.html
func (ss *SecretService) prompt(path dbus.ObjectPath) error {
	// Subscribe to signals on the prompt object so we can get the
	// "Completed" signal when the prompt is complete. We do this
	// before calling Prompt to ensure we do not miss it. Only one
	// signal should ever arrive on the channel, so make it a
	// buffererd channel of size 1 so the dbus library wont drop
	// the signal.
	ch := make(chan *dbus.Signal, 1)
	ss.conn.Signal(ch)
	defer ss.conn.RemoveSignal(ch)
	if err := ss.conn.AddMatchSignal(dbus.WithMatchObjectPath(path)); err != nil {
		return err
	}
	defer ss.conn.RemoveMatchSignal(dbus.WithMatchObjectPath(path)) //nolint:errcheck

	svc := ss.conn.Object("org.freedesktop.secrets", path)
	call := svc.Call("org.freedesktop.Secret.Prompt.Prompt", 0, "")
	if call.Err != nil {
		return call.Err
	}

	for sig := range ch {
		if sig.Name != "org.freedesktop.Secret.Prompt.Completed" {
			continue
		}
		var cancelled bool
		var unlockPaths []dbus.ObjectPath
		if err := dbus.Store(sig.Body, &cancelled, &unlockPaths); err != nil {
			return err
		}
		if cancelled {
			return errors.New("unlock cancelled by user")
		}
		break
	}
	return nil
}
