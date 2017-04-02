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
	"encoding/json"
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/bradfitz/gomemcache/memcache"
)

// MemcachedSessionHandler is a SessionHandler that wraps another handler and
// queries memcached first and only performs a query on the wrapper handler
// when the memcached lookup failed.
//
// A key k gets stored as "skey<SOME-RANDOM-INT>:k" in memcached.
// Note that the max length for keys in memcached is 250, so don't set the
// session key length to something too big.
// The data associated with the key is stored as a json string.
//
// The function ConvertUser is used to transform a value stored in the json
// string back to its original type, so you probably have to implement your
// own variant:
// The user information is of type interface{} s.t. you can use whatever type
// you want. When storing the user information the user key is transformed to a
// string with the String() method. You want to make sure that when retrieving
// the data your key gets transformed to the correct data type.
// The default implementation assumes that the key type is uint64.
//
// Memcached errors are not returned in the functions but printed to the log.
//
// For more examples read the wiki: https://github.com/FabianWe/goauth/wiki/Using-Memcached-for-Session-Lookups
type MemcachedSessionHandler struct {
	// Parent is the handler wrapped by memcached.
	Parent SessionHandler

	// Client is the memcached client to connect to memcached.
	Client *memcache.Client

	// SessionPrefix is the prefix for keys stored in memcached, default is "skey".
	SessionPrefix string

	// ConvertUser is the function used to transform the string representation
	// of the user identification back to its original type.
	// The default assumes uint64.
	ConvertUser func(val string) (interface{}, error)

	// Expiration value defines how long an entry in memcached is considered
	// valid.
	// From the memcached docs (https://github.com/memcached/memcached/wiki/Programming#expiration):
	// "Expiration times are specified in unsigned integer seconds. They can be
	// set from 0, meaning "never expire", to 30 days (60 * 60 * 24 * 30).
	// Any time higher than 30 days is interpreted as a unix timestamp date.
	// If you want to expire an object on january 1st of next year,
	// this is how you do that."
	// Defauts to 3600 (1 hour).
	Expiration int32

	// currentSessionKeyIdentifier currently used random identifier.
	currentSessionKeyIdentifier int

	// mutex is used to synchronize access to the currentSessionKeyIdentifier.
	// getCurrentSessionKeyIdentifier sets a read lock,
	// updateCurrentSessionKeyIdentifier sets a write lock.
	mutex sync.RWMutex

	// r is the random number generator.
	r *rand.Rand
}

// NewMemcachedSessionHandler returns a new MemcachedSessionHandler that
// uses parent as the main handler to query when a memcached lookup fails.
// It sets Expiration to 3600 (which means 1 hour) and SessionPrefix to "skey".
func NewMemcachedSessionHandler(parent SessionHandler, client *memcache.Client) *MemcachedSessionHandler {
	defaultFunc := func(val string) (interface{}, error) {
		var res uint64
		res, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return nil, err
		}
		return res, nil
	}
	r := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
	return &MemcachedSessionHandler{Parent: parent, Client: client,
		SessionPrefix: "skey:", currentSessionKeyIdentifier: r.Int(),
		ConvertUser: defaultFunc, Expiration: 3600,
		r: r}
}

// getCurrentSessionKeyIdentifier returns the currently used random identifier.
func (handler *MemcachedSessionHandler) getCurrentSessionKeyIdentifier() int {
	handler.mutex.RLock()
	defer handler.mutex.RUnlock()
	return handler.currentSessionKeyIdentifier
}

// updateCurrentSessionKeyIdentifier set the currently used random identifier
// to a new random int number.
func (handler *MemcachedSessionHandler) updateCurrentSessionKeyIdentifier() {
	handler.mutex.Lock()
	handler.currentSessionKeyIdentifier = handler.r.Int()
	defer handler.mutex.Unlock()
}

// formatKeyEntry returns the string to be stored in memcached:
// "skey<SOME-RANDOM-INT>:<KEY>".
func (handler *MemcachedSessionHandler) formatKeyEntry(key string) string {
	return fmt.Sprintf("%s%d:%s",
		handler.SessionPrefix,
		handler.getCurrentSessionKeyIdentifier(),
		key)
}

// formatJSONData transforms the SessionKeyData in a json object to be stored
// in memcached:
// It uses a dictionary {u: User, c: CreationTime, v: ValidUntil}
// Dates are stored in the format "2006-01-02 15:04:05"
func (handler *MemcachedSessionHandler) formatJSONData(data *SessionKeyData) ([]byte, error) {
	values := map[string]interface{}{"u": fmt.Sprintf("%v", data.User),
		"c": data.CreationTime.Format("2006-01-02 15:04:05"),
		"v": data.ValidUntil.Format("2006-01-02 15:04:05")}
	return json.Marshal(values)
}

// parseJSONData parses the json encoded SessionKeyData.
func (handler *MemcachedSessionHandler) parseJSONData(b []byte) (*SessionKeyData, error) {
	type parseType struct {
		User     string `json:"u"`
		Creation string `json:"c"`
		Valid    string `json:"v"`
	}
	var intermediate parseType
	err := json.Unmarshal(b, &intermediate)
	if err != nil {
		return nil, err
	}
	user, userErr := handler.ConvertUser(intermediate.User)
	if userErr != nil {
		return nil, userErr
	}
	creation, creationErr := time.Parse("2006-01-02 15:04:05", intermediate.Creation)
	if creationErr != nil {
		return nil, creationErr
	}
	valid, validErr := time.Parse("2006-01-02 15:04:05", intermediate.Valid)
	if validErr != nil {
		return nil, validErr
	}
	return NewSessionKeyData(user, creation, valid), nil
}

// Init simply calls Parent.Init()
func (handler *MemcachedSessionHandler) Init() error {
	return handler.Parent.Init()
}

// setMemcached formats the given session key and the SessionKeyData and
// stores the entry in memcached.
func (handler *MemcachedSessionHandler) setMemcached(key string, value *SessionKeyData) {
	memcachedKey := handler.formatKeyEntry(key)
	json, jsonErr := handler.formatJSONData(value)
	if jsonErr != nil {
		log.WithError(jsonErr).Warn("goauth: Insertion in memcached failed, can't encode json")
		return
	}
	// finally set
	if err := handler.Client.Set(&memcache.Item{Key: memcachedKey, Value: json, Expiration: handler.Expiration}); err != nil {
		log.WithError(err).Warn("goauth: Insertion in memcached failed, unkown error.")
	}
}

// GetData works the following way: First lookup the entry in memcached, if
// this worked return the value.
// Otherwise we ask the parent. If lookup on the parent succeeds we add the
// entry in memcached as well.
func (handler *MemcachedSessionHandler) GetData(key string) (*SessionKeyData, error) {
	// first get the key we store in memcached
	memcachedKey := handler.formatKeyEntry(key)
	// try to get the key from memcached
	item, err := handler.Client.Get(memcachedKey)
	if err != nil {
		// just ask the parent
		// if parent returns a result add it to memcached
		parentData, parentErr := handler.Parent.GetData(key)
		if parentErr != nil {
			return parentData, parentErr
		}
		if err != memcache.ErrCacheMiss {
			log.WithError(err).Warn("goauth: memcached returned an unkown error")
			// don't add it something seems to be wrong...
			return parentData, parentErr
		}
		// insert to memcached
		handler.setMemcached(key, parentData)
		return parentData, parentErr
	}
	// entry was found
	data, jsonErr := handler.parseJSONData(item.Value)
	if jsonErr != nil {
		log.WithError(jsonErr).Warn("goauth: memcached result parsing failed, this should not happen... Asking parent")
		return handler.Parent.GetData(key)
	}
	return data, nil
}

// CreateEntry creates an entry in the parent, if that succeeds it also adds
// an entry in memcached.
func (handler *MemcachedSessionHandler) CreateEntry(user UserKeyType, key string, validDuration time.Duration) (*SessionKeyData, error) {
	// first add to parent, store the result here as well
	data, parentErr := handler.Parent.CreateEntry(user, key, validDuration)
	if parentErr != nil {
		return data, parentErr
	}
	handler.setMemcached(key, data)
	return data, parentErr
}

// DeleteEntriesForUser invalidates ALL entries in memcached by creating
// a new random number. After that it calls DeleteEntriesForUser on the parent.
func (handler *MemcachedSessionHandler) DeleteEntriesForUser(user UserKeyType) (int64, error) {
	// create a new random int, this invalidates all keys, not just for the user!
	handler.updateCurrentSessionKeyIdentifier()
	return handler.Parent.DeleteEntriesForUser(user)
}

// DeleteInvalidKeys only calls DeleteInvalidKeys on the parent.
func (handler *MemcachedSessionHandler) DeleteInvalidKeys() (int64, error) {
	// actually we do nothing...
	return handler.Parent.DeleteInvalidKeys()
}

// DeleteKey first deletes the entry from memcached and then from the parent.
func (handler *MemcachedSessionHandler) DeleteKey(key string) error {
	// remove the key from memcached
	if err := handler.Client.Delete(handler.formatKeyEntry(key)); err != nil && err != memcache.ErrCacheMiss {
		log.WithError(err).Warn("goauth: Unkown memcached error")
	}
	return handler.Parent.DeleteKey(key)
}
