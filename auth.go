// The MIT License (MIT)

// Copyright (c) 2017 Fabian Wenzelmann

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package goauth

import (
	"context"
	"encoding/base64"
	"errors"

	log "github.com/sirupsen/logrus"

	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

// UserKeyType is a special type that is used for user keys. User keys can be
// for example strings (username) or ints (uid).
// It is used to indentify a user for example in database. So it should be
// something that can be stored in a database or in dicts.
// Note that if it's something more complex you must register it with
// gob.Register s.t. it can be stored in the session.
// See http://www.gorillatoolkit.org/pkg/sessions for example.
// "Basic" types such as int, string, ... work fine.
type UserKeyType interface{}

// ErrKeyNotFound is the error that is returned whenever you try to lookup
// the information stored for a certain key but that key does not exist.
var ErrKeyNotFound = errors.New("No entry for key was found")

const (
	// DefaultRandomByteLength is the default length for random bytes array, this
	// creates random base64 strings of length 64.
	DefaultRandomByteLength = 48

	// DefaultKeyLength is the length of the random base 64 strings, it should
	// be set in accordance with DefaultRandomByteLength.
	DefaultKeyLength = 64
)

// SessionKeyData type is used as a result in a key lookup. It contains the user
// that corresponds to the session key and the time it was created and the time
// when the key becomes invalid.
// All methods that accept a *SessionKeyData should assume that the lookup
// failed if it is nil.
// The time should *always* be in UTC so the behaviour is consistent (and UTC
// is usually the easiest option).
// A key is considered valid if currentTime <= ValidUntil. You can use
// the helper functions KeyValid(now, ValidUntil) or KeyInvalid(now, ValidUntil),
// or directly use these constraints directly in your database queries.
type SessionKeyData struct {
	// User is the user connected with a key.
	User UserKeyType

	// CreationTime is the time the key was created.
	CreationTime time.Time

	// ValidUntil is the time until the key is considered valid.
	ValidUntil time.Time
}

// NewSessionKeyData creates a new SessionKeyData instance with the given
// values.
// If you want to create a new SessionKeyData object to insert it somewhere
// you should use CurrentTimeKeyData for consistent behaviour.
func NewSessionKeyData(user UserKeyType, creationTime, validUntil time.Time) *SessionKeyData {
	return &SessionKeyData{User: user, CreationTime: creationTime, ValidUntil: validUntil}
}

// CurrentTime returns the current type. For consistent behaviour you should
// always use this method to get the current time.
// It returns time.Now().UTC()
func CurrentTime() time.Time {
	return time.Now().UTC()
}

// CurrentTimeKeyData creates a new SessionKeyData object with the current time.
// It should be use by all handlers s.t. the behaviour is consistent.
// it creates the time object in UTC.
func CurrentTimeKeyData(user UserKeyType, validDuration time.Duration) *SessionKeyData {
	now := CurrentTime()
	validUntil := now.Add(validDuration)
	return NewSessionKeyData(user, now, validUntil)
}

// KeyInvalid checks if a key is invalid.
// A key is considered invalid if now is after validUntil.
// The parameter now exists s.t. you can use the same now in all queries, so
// usually you create now once at the beginning of your function.
func KeyInvalid(now, validUntil time.Time) bool {
	return now.After(validUntil)
}

// KeyValid checks if a key is still valid.
// This is the case if validUntil <= now.
// The parameter now exists s.t. you can use the same now in all queries, so
// usually you create now once at the beginning of your function.
func KeyValid(now, validUntil time.Time) bool {
	return !KeyInvalid(now, validUntil)
}

// GenRandomBase64 returns a random base64 encoded string based on a random byte
// sequence of size n. Note that the returned string does not have length n,
// n is the size of the byte array!
// To represent n bytes in base64 you need 4*(n/3) rounded up to the next
// multiple of 4. So this will be the length of the returned string.
// For example use n = 24 for keys of length 32, n = 48 for keys of length 64
// and n = 96 for keys of length 128.
// Use n = -1 to use the default value which is 48, so a random string of
// length 64.
func GenRandomBase64(n int) (string, error) {
	if n <= 0 {
		n = DefaultRandomByteLength
	}
	b := securecookie.GenerateRandomKey(n)
	if b == nil {
		return "", errors.New("Can't generate random bytes, probably an error with your random generator, do not continue!")
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// SessionHandler is the interface to store and retrieve session keys and
// the associated SessionKeyData objects.
type SessionHandler interface {
	// Init initializes the storage s.t. it is ready for use. This could be for
	// example a create table statement. You should however not overwrite
	// any existing data (if you have any).
	// For example only create a table if it does not already exist.
	// This method should be called each time you start your program.
	Init() error

	// GetData is a function to get the user data for a given key.
	// It should return nil and KeyNotFoundErr if the key was not found
	// and nil and some other error in case something went wrong during lookup.
	// If an err != nil is returned it must always return *SessionKeyData != nil.
	GetData(key string) (*SessionKeyData, error)

	// CreateEntry creates a new entry for the user with the given key.
	// It should call CurrentTimeKeyData and add this value.
	// Return an error if one occurred, maybe you should check if the
	// key already exists, however this is very unlikely.
	// Return error != nil only if the insertion really failed.
	// It returns the inserted data if everything went ok.
	CreateEntry(user UserKeyType, key string, validDuration time.Duration) (*SessionKeyData, error)

	// DeleteEntriesForUser removes all keys for the given user.
	// It returns the number of removed entries and returns an error if something
	// went wrong.
	DeleteEntriesForUser(user UserKeyType) (int64, error)

	// DeleteInvalidKeys removes all invalid keys from the storage.
	// Returns the number of removed keys and an error if something went wrong.
	DeleteInvalidKeys() (int64, error)

	// DeleteKey removes the key from the storage, return an error if one occurred.
	// It doesn't return an error if the key is invalid / not found!
	DeleteKey(key string) error
}

// SessionController uses a SessionHandler to query the storage and add
// additional functionality. It is used as the main anchorpoint for user
// authentication.
// It creates sessions called SessionName (the field in this struct) and stores
// in that session the key in session.Values["key"].
// NumBytes is the length of the random byte slice, see GenRandomBase64
// for details about this parameter.
type SessionController struct {
	SessionHandler
	NumBytes    int
	SessionName string
}

// NewSessionController creates a new session controller given a SessionHandler,
// the size of the random byte slice
// If you use another key length or session name set the values after calling
// NewSessionController, i.e. controller.NumBytes = ... and
// controller.SessionName = ...
func NewSessionController(h SessionHandler) *SessionController {
	return &SessionController{SessionHandler: h, NumBytes: DefaultRandomByteLength,
		SessionName: "user-auth"}
}

// AddKey adds a new entry to the storage.
// This function returns either nil, "" and some error if something went wrong
// or the SessionKeyData instance, the key that was used to identify this
// session and nil.
func (c *SessionController) AddKey(user UserKeyType, validDuration time.Duration) (*SessionKeyData, string, error) {
	key, genErr := GenRandomBase64(c.NumBytes)
	if genErr != nil {
		return nil, "", genErr
	}
	data, insertErr := c.CreateEntry(user, key, validDuration)
	if insertErr != nil {
		return nil, "", insertErr
	}
	// everything ok
	return data, key, nil
}

const (
	// SessionKey is the key to store the auth-key in a gorilla session.
	// So we store the create create for the auth session in
	// session.Values[SessionKey].
	SessionKey = "key"
)

// ErrInvalidKey is the error that will be returned if a key was found in the
// storage but the key is not valid anymore.
var ErrInvalidKey = errors.New("The key is not valid any more.")

// ErrNotAuthSession is the error that will be returned if a gorialla session
// does not have the SessionKey in session.Values. This usually means that
// the user does not have a session yet and needs to login.
var ErrNotAuthSession = errors.New("The session is not a valid auth session.")

// ValidateSession validates the key that is stored in the session.
// This function will try to get a session that is called SessionName (so
// usually the session "user-auth"). If an error occurred while trying to get
// the session it returns nil, nil and the error.
// If the found session does not have the required SessionKey value (the one
// we store the key that connects the gorilla session to our storage)
// this function returns nil, the session, and ErrNotAuthSession.
// If there is a user auth key stored in the session it will lookup
// the key in the underlying storage. It then returns nil, the session and
// KeyNotFoundErr if the key was not found in the storage (for example the key
// was deleted because it was not valid any more).
// If the key is still present in the storage but not valid any more
// InvalidKeyErr will be returned. Otherwise it returns the data found in the
// storage, the auth session object (for possible further processing) and nil
// as error.
// Otherwise it returns any error that may have happend while asking the
// underlying storage, such as database errors.
// So summarize:
//
// If it returns a *SessionKeyData != nil everything is ok, you can get the
// user information from the SessionKeyData element.
//
// If it returns nil as for the SessionKeyData something went wrong:
// (1) Something was wrong with the store (2) err == NotAuthSessionErr no
// authentication information was found, so probably the user has to log in
// and create a new sessionn (3) err == KeyNotFoundErr auth information was
// provided, but the key was not found, so either someone tried a random key
// or the session of the user simply expired and was therefore deleted from
// storage (4) err == InvalidKeyErr the key was still found in the database
// but is not valid any more, so probably the user hast to login again.
//
// This method will automatically update the session.MaxAge to the time
// the key is still considered valid. If the key is invalid it will set the
// MaxAge to -1.
//
// This method will not call session.Save!
//
// See examples for how to use this method.
func (c *SessionController) ValidateSession(r *http.Request, store sessions.Store) (*SessionKeyData, *sessions.Session, error) {
	now := CurrentTime()
	// first get the session
	session, err := store.Get(r, c.SessionName)
	if err != nil {
		return nil, nil, err
	}

	// check for the key value stored in session
	keyVal, hasKey := session.Values[SessionKey]

	if !hasKey {
		return nil, session, ErrNotAuthSession
	}

	key, ok := keyVal.(string)
	if !ok {
		return nil, session, errors.New("Internal lookup error. \"key\" is present in the session but not of type string.")
	}

	// try to get the information out of the underlying storage
	info, err := c.GetData(key)
	if err != nil {
		return nil, session, err
	}

	// now info is not allowed to be nil
	// so we validate the entry and update the max age of the session, update to
	// the time that is still left

	if KeyInvalid(now, info.ValidUntil) {
		session.Options.MaxAge = -1
		return nil, session, ErrInvalidKey
	}

	durationLeft := info.ValidUntil.Sub(now)
	session.Options.MaxAge = int(durationLeft / time.Second)

	// everything is fine, so now return everything: the user should be considered
	// as logged in
	return info, session, nil
}

// CreateAuthSession will create a new session and add it to the underlying
// storage.
// It returns the data that was stored for the key, the generated key
// the goriall session the value was stored in and any error.
// If err != nil you should always consider it as a failure and assume that
// something went wrong on your server (internal server error).
// It will return the session even if err != nil and we didn't store the key,
// but that is not really important since you should always handle it as an
// error.
//
// It will set the session.MaxAge to the correct value, but again will not
// call session.Save!
func (c *SessionController) CreateAuthSession(r *http.Request, store sessions.Store,
	user UserKeyType, validDuration time.Duration) (*SessionKeyData, string, *sessions.Session, error) {
	session, err := store.Get(r, c.SessionName)
	if err != nil {
		return nil, "", nil, err
	}
	data, key, err := c.AddKey(user, validDuration)
	if err != nil {
		return nil, "", session, err
	}
	session.Values[SessionKey] = key
	session.Options.MaxAge = int(validDuration / time.Second)
	// everything ok
	return data, key, session, nil
}

// EndSession deletes the key stored in session.Values from the underlying
// storage.
// If the session does not contain an auth key it will not return an,
// i.e. if the session is not an auth session we can't look up the key.
// It will then return nil as an error. So an error is only returned if
// something really went wrong.
//
// The session.MaxAge will be set to -1.
func (c *SessionController) EndSession(r *http.Request, store sessions.Store) error {
	session, err := store.Get(r, c.SessionName)
	if err != nil {
		return err
	}

	// check for the key value stored in session
	keyVal, hasKey := session.Values[SessionKey]

	if !hasKey {
		return nil
	}

	key, ok := keyVal.(string)
	if !ok {
		return errors.New("Internal lookup error. \"key\" is present in the session but not of type string.")
	}
	// set the session age to -1
	session.Options.MaxAge = -1
	return c.DeleteKey(key)
}

// DeleteEntriesDaemon starts a goroutine that runs forever and deletes invalid
// keys from the underlying storage.
//
// The sleep parameter specifies how often entries should be deleted.
// Something reasonable would be for example to do this every day.
//
// When the daemon gets started it immediately deletes invalid keys, so make
// sure you start it after calling init.
//
// The context parameter can be set to nil and the daemon runs forever.
// If it is set to a context however it will listen on the context.Done
// channel and stop once it receives a stop signal.
// See the wiki for an example.
func (c *SessionController) DeleteEntriesDaemon(sleep time.Duration, ctx context.Context, reportErr bool) {
	go func() {
		if ctx == nil {
			for {
				if _, err := c.DeleteInvalidKeys(); reportErr && err != nil {
					log.WithError(err).Error("goauth: Error deleting invalid keys.")
				}
				time.Sleep(sleep)
			}
		} else {
			// we could use time.Tick but I find this more suitable...
			next := make(chan bool, 1)
			next <- true
			for {
				select {
				case <-ctx.Done():
					return
				case <-next:
					if _, err := c.DeleteInvalidKeys(); reportErr && err != nil {
						log.WithError(err).Error("goauth: Error deleting invalid keys.")
					}
					go func() {
						time.Sleep(sleep)
						next <- true
					}()
				}
			}
		}
	}()
}
