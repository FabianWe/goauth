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
	"errors"
	"sync"
	"time"
)

// This type implements the SessionHandler interface using an in memory
// map.
// This map will be lost after you stop your application.
type InMemoryHandler struct {
	keys  map[string]*SessionKeyData
	mutex sync.RWMutex
}

func NewInMemoryHandler() *InMemoryHandler {
	return &InMemoryHandler{keys: make(map[string]*SessionKeyData)}
}

func NewInMemoryController() *SessionController {
	return NewSessionController(NewInMemoryHandler())
}

func (h *InMemoryHandler) Init() error {
	return nil
}

func (h *InMemoryHandler) GetData(key string) (*SessionKeyData, error) {
	h.mutex.RLock()
	value, ok := h.keys[key]
	h.mutex.RUnlock()
	if ok {
		return value, nil
	} else {
		return nil, ErrKeyNotFound
	}
}

func (h *InMemoryHandler) CreateEntry(user UserKeyType, key string, validDuration time.Duration) (*SessionKeyData, error) {
	h.mutex.Lock()
	if _, hasEntry := h.keys[key]; hasEntry {
		h.mutex.Unlock()
		return nil, errors.New("Key already exists")
	}
	data := CurrentTimeKeyData(user, validDuration)
	h.keys[key] = data
	h.mutex.Unlock()
	return data, nil
}

func (h *InMemoryHandler) DeleteEntriesForUser(user UserKeyType) (int64, error) {
	var removed int64 = 0
	h.mutex.Lock()
	for key, value := range h.keys {
		if value.User == user {
			// delete entry
			delete(h.keys, key)
			removed++
		}
	}
	h.mutex.Unlock()
	return removed, nil
}

func (h *InMemoryHandler) DeleteInvalidKeys() (int64, error) {
	var removed int64 = 0
	now := CurrentTime()
	h.mutex.Lock()
	for key, value := range h.keys {
		if KeyInvalid(now, value.ValidUntil) {
			delete(h.keys, key)
			removed++
		}
	}
	h.mutex.Unlock()
	return removed, nil
}

func (h *InMemoryHandler) DeleteKey(key string) error {
	h.mutex.Lock()
	delete(h.keys, key)
	h.mutex.Unlock()
	return nil
}
