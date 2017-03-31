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
	"log"
	"math/rand"
	"strconv"
	"sync"
	"time"

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
	return &MemcachedSessionHandler{Parent: parent, Client: client,
		SessionPrefix: "skey:", currentSessionKeyIdentifier: rand.Int(),
		ConvertUser: defaultFunc, Expiration: 3600}
}

func (handler *MemcachedSessionHandler) getCurrentSessionKeyIdentifier() int {
	handler.mutex.RLock()
	defer handler.mutex.RUnlock()
	return handler.currentSessionKeyIdentifier
}

func (handler *MemcachedSessionHandler) updateCurrentSessionKeyIdentifier() {
	handler.mutex.Lock()
	handler.currentSessionKeyIdentifier = rand.Int()
	defer handler.mutex.Unlock()
}

func (handler *MemcachedSessionHandler) formatKeyEntry(key string) string {
	return fmt.Sprintf("%s%d:%s",
		handler.SessionPrefix,
		handler.getCurrentSessionKeyIdentifier(),
		key)
}

func (handler *MemcachedSessionHandler) FormatJSONData(data *SessionKeyData) ([]byte, error) {
	values := map[string]interface{}{"user": fmt.Sprintf("%v", data.User),
		"creation": data.CreationTime.Format("2006-01-02 15:04:05"),
		"valid":    data.ValidUntil.Format("2006-01-02 15:04:05")}
	return json.Marshal(values)
}

// TODO make private
func (handler *MemcachedSessionHandler) ParseJSONData(b []byte) (*SessionKeyData, error) {
	type parseType struct {
		User, Creation, Valid string
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

func (handler *MemcachedSessionHandler) GetData(key string) (*SessionKeyData, error) {
	// first get the key we store in memcached
	memcachedKey := handler.formatKeyEntry(key)
	// try to get the key from memcached
	item, err := handler.Client.Get(memcachedKey)
	if err != nil {
		if err == memcache.ErrCacheMiss {
			// everything ok, just as the parent
			return handler.Parent.GetData(key)
		}
		log.Printf("WARNING: memcached returned an unkown error: %v\n", err)
	}
	// entry was found
	data, jsonErr := handler.ParseJSONData(item.Value)
	if jsonErr != nil {
		log.Println("WARNING: memcached result parsing failed, this should not happen... Asking parent")
		return handler.Parent.GetData(key)
	}
	return data, nil
}

func (handler *MemcachedSessionHandler) CreateEntry(user UserKeyType, key string, validDuration time.Duration) (*SessionKeyData, error) {
	// first add to parent, store the result here as well
	data, parentErr := handler.Parent.CreateEntry(user, key, validDuration)
	if parentErr != nil {
		return nil, parentErr
	}
	memcachedKey := handler.formatKeyEntry(key)
	// insert here as well
	json, jsonErr := handler.FormatJSONData(data)
	if jsonErr != nil {
		log.Println("WARNING: Insertion in memcached failed, can't encode json")
		return data, nil
	}
	// finally set
	if err := handler.Client.Set(&memcache.Item{Key: memcachedKey, Value: json, Expiration: handler.Expiration}); err != nil {
		log.Println("WARNING: Insertion in memcached failed, unkown error: ", err)
	}
	return data, nil
}

func (handler *MemcachedSessionHandler) DeleteEntriesForUser(user UserKeyType) (int64, error) {
	// create a new random int, this invalidates all keys, not just for the user!
	handler.updateCurrentSessionKeyIdentifier()
	return handler.Parent.DeleteEntriesForUser(user)
}

func (handler *MemcachedSessionHandler) DeleteInvalidKeys() (int64, error) {
	// invalidate all keys
	handler.updateCurrentSessionKeyIdentifier()
	return handler.Parent.DeleteInvalidKeys()
}

func (handler *MemcachedSessionHandler) DeleteKey(key string) error {
	// remove the key from memcached
	if err := handler.Client.Delete(handler.formatKeyEntry(key)); err != nil && err != memcache.ErrCacheMiss {
		log.Println("WARNING: Unkown memcached error: ", err)
	}
	return handler.Parent.DeleteKey(key)
}