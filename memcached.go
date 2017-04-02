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

// TODO expiration, set to a rather small value

type MemcachedSessionHandler struct {
	Parent        SessionHandler
	Client        *memcache.Client
	SessionPrefix string
	ConvertUser   func(val string) (interface{}, error)
	Expiration    int32

	currentSessionKeyIdentifier int
	mutex                       sync.RWMutex
	r                           *rand.Rand
}

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

func (handler *MemcachedSessionHandler) getCurrentSessionKeyIdentifier() int {
	handler.mutex.RLock()
	defer handler.mutex.RUnlock()
	return handler.currentSessionKeyIdentifier
}

func (handler *MemcachedSessionHandler) updateCurrentSessionKeyIdentifier() {
	handler.mutex.Lock()
	handler.currentSessionKeyIdentifier = handler.r.Int()
	defer handler.mutex.Unlock()
}

func (handler *MemcachedSessionHandler) formatKeyEntry(key string) string {
	return fmt.Sprintf("%s%d:%s",
		handler.SessionPrefix,
		handler.getCurrentSessionKeyIdentifier(),
		key)
}

func (handler *MemcachedSessionHandler) FormatJSONData(data *SessionKeyData) ([]byte, error) {
	values := map[string]interface{}{"u": fmt.Sprintf("%v", data.User),
		"c": data.CreationTime.Format("2006-01-02 15:04:05"),
		"v": data.ValidUntil.Format("2006-01-02 15:04:05")}
	return json.Marshal(values)
}

// TODO make private
func (handler *MemcachedSessionHandler) ParseJSONData(b []byte) (*SessionKeyData, error) {
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

func (handler *MemcachedSessionHandler) Init() error {
	return handler.Parent.Init()
}

func (handler *MemcachedSessionHandler) setMemcached(key string, value *SessionKeyData) {
	memcachedKey := handler.formatKeyEntry(key)
	json, jsonErr := handler.FormatJSONData(value)
	if jsonErr != nil {
		log.WithError(jsonErr).Warn("Insertion in memcached failed, can't encode json")
		return
	}
	// finally set
	if err := handler.Client.Set(&memcache.Item{Key: memcachedKey, Value: json, Expiration: handler.Expiration}); err != nil {
		log.WithError(err).Warn("Insertion in memcached failed, unkown error.")
	}
}

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
			log.WithError(err).Warn("memcached returned an unkown error")
			// don't add it something seems to be wrong...
			return parentData, parentErr
		}
		// insert to memcached
		handler.setMemcached(key, parentData)
		return parentData, parentErr
	}
	// entry was found
	data, jsonErr := handler.ParseJSONData(item.Value)
	if jsonErr != nil {
		log.WithError(jsonErr).Warn("memcached result parsing failed, this should not happen... Asking parent")
		return handler.Parent.GetData(key)
	}
	return data, nil
}

func (handler *MemcachedSessionHandler) CreateEntry(user UserKeyType, key string, validDuration time.Duration) (*SessionKeyData, error) {
	// first add to parent, store the result here as well
	data, parentErr := handler.Parent.CreateEntry(user, key, validDuration)
	if parentErr != nil {
		return data, parentErr
	}
	handler.setMemcached(key, data)
	return data, parentErr
}

func (handler *MemcachedSessionHandler) DeleteEntriesForUser(user UserKeyType) (int64, error) {
	// create a new random int, this invalidates all keys, not just for the user!
	handler.updateCurrentSessionKeyIdentifier()
	return handler.Parent.DeleteEntriesForUser(user)
}

func (handler *MemcachedSessionHandler) DeleteInvalidKeys() (int64, error) {
	// actually we do nothing...
	return handler.Parent.DeleteInvalidKeys()
}

func (handler *MemcachedSessionHandler) DeleteKey(key string) error {
	// remove the key from memcached
	if err := handler.Client.Delete(handler.formatKeyEntry(key)); err != nil && err != memcache.ErrCacheMiss {
		log.WithError(err).Warn("Unkown memcached error")
	}
	return handler.Parent.DeleteKey(key)
}
