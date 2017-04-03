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
	"fmt"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/go-redis/redis"
)

// Sessions stuff

// RedisSessionHandler is a session Handler using redis.
// This works the following way:
// All session keys are added to redis in the form
// "skey:<key>"
// Users are stored as strings so the same as for memcached applies:
// To retrieve the user correctly for your type you have to define a different
// ConvertUser method. The default one assumes uint64.
// Also for each user we store a set of the keys associated with the user.
// These entries are stored in the form "usessions:<user>".
// Every time a new entry is created we add the new key to this set and delete
// keys that were already deleted from this set.
// This way we take care that not all sessions, even those that were deleted
// by redis, will be stored forever.
// So old sessions get deleted either when the user set entry expires
// always set to the maximum of all stored sessions or the user logs in again.
// So at some point those entries will be deleted.
// This is some additional overhead in CreateEntry but should be absolutely
// fine.
//
// All expiration stuff is handled by redis, so the DeleteInvalidKeys does
// actually nothing.
type RedisSessionHandler struct {
	// Client is the client to connect to redis.
	Client *redis.Client

	// SessionPrefix is the prefix that gets appended to all entries in redis
	// that contain session keys.
	// Defaults to "skey:" in NewRedisSessionHandler.
	// UserPrefix is the prefix that gets appended to all entries in redis
	// that contain user sets.
	// Defaults to "usessions:" in NewRedisSessionHandler.
	SessionPrefix, UserPrefix string

	// ConvertUser is the function used to transform the string representation
	// of the user identification back to its original type.
	// The default assumes uint64.
	ConvertUser func(val string) (interface{}, error)
}

// NewRedisSessionHandler creates a new RedisSessionHandler.
func NewRedisSessionHandler(client *redis.Client) *RedisSessionHandler {
	defaultFunc := func(val string) (interface{}, error) {
		var res uint64
		res, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return nil, err
		}
		return res, nil
	}
	return &RedisSessionHandler{Client: client, SessionPrefix: "skey:",
		UserPrefix: "usessions:", ConvertUser: defaultFunc}
}

// Init is a NOOP for for redis.
func (handler *RedisSessionHandler) Init() error {
	return nil
}

// delUserKeys deletes all keys given the userIdentifier, i.e. usessions:
// If delAll is true all keys for that user get deleted, otherwise
// only those keys that don't refer to a valid session key anymore.
func (handler *RedisSessionHandler) delUserKeys(userIdentifier string, delAll bool) (int64, error) {
	// now delete all invalid entries
	if allUserKeys, getErr := handler.Client.SMembers(userIdentifier).Result(); getErr != nil {
		log.WithError(getErr).Warn("goauth(redis): Can't retrieve keys for user")
		return 0, getErr
	} else {
		keysForDelete := make([]string, 0)
		for _, userKey := range allUserKeys {
			if delAll {
				keysForDelete = append(keysForDelete, userKey)
			} else {
				if exists, existsErr := handler.Client.Exists(handler.SessionPrefix + userKey).Result(); existsErr != nil {
					log.WithError(existsErr).Warn("goauth(redis): Can't check status of key")
				} else if exists == 0 {
					// delete
					keysForDelete = append(keysForDelete, handler.SessionPrefix+userKey)
				}
			}
		}
		// issue the delete command
		if len(keysForDelete) > 0 {
			if numDel, delErr := handler.Client.Del(keysForDelete...).Result(); delErr != nil {
				log.WithError(delErr).Warn("Can't delete keys for user")
				return 0, delErr
			} else {
				if numDel > 0 {
					log.Infof("Deleted %d keys from users set", numDel)
				}
				return numDel, nil
			}
		} else {
			return 0, nil
		}
	}
}

// CreateEntry adds a new entry.
// Note that in redis this also includes to add a new key to the user
// sessions set and removing keys from that set that no longer exist.
// So this may take some time longer than other methods (especially if a user
// has multiple sessions). But this is still fine if you don't add thousands
// of keys within seconds ;).
func (handler *RedisSessionHandler) CreateEntry(user UserKeyType, key string, validDuration time.Duration) (*SessionKeyData, error) {
	data := CurrentTimeKeyData(user, validDuration)
	redisKey := handler.SessionPrefix + key
	err := handler.Client.HMSet(redisKey,
		map[string]interface{}{
			"User":         fmt.Sprintf("%v", user),
			"CreationTime": data.CreationTime.Format("2006-01-02 15:04:05"),
			"ValidUntil":   data.ValidUntil.Format("2006-01-02 15:04:05"),
		}).Err()
	if err != nil {
		return nil, err
	}
	err = handler.Client.Expire(redisKey, validDuration).Err()
	if err != nil {
		return nil, err
	}
	go func() {
		userIdentifier := fmt.Sprintf("%s%v", handler.UserPrefix, user)
		if saddErr := handler.Client.SAdd(userIdentifier, key).Err(); saddErr != nil {
			log.WithError(saddErr).Warn("goauth(redis): Can't append key to user key set.")
		}
		// get current TTL, set Expiration to max of TTL and validDuration
		userExp := validDuration
		if ttl, ttlErr := handler.Client.TTL(userIdentifier).Result(); ttlErr != nil {
			log.WithError(ttlErr).Warn("goauth(redis): Can't get TTL of user key set, using expiration")
		} else {
			// if ttl is after validDuration, set userExp to ttl
			if ttl > validDuration {
				userExp = ttl
			}
		}
		if expErr := handler.Client.Expire(userIdentifier, userExp).Err(); expErr != nil {
			log.WithError(expErr).Warn("goauth(redis): Can't set Expire for user key set")
		}
		handler.delUserKeys(userIdentifier, false)
	}()
	return data, nil
}

func (handler *RedisSessionHandler) GetData(key string) (*SessionKeyData, error) {
	entry, err := handler.Client.HMGet(handler.SessionPrefix+key, "User", "CreationTime", "ValidUntil").Result()
	if err != nil {
		return nil, err
	}
	if entry[0] == nil {
		return nil, ErrKeyNotFound
	}
	result := &SessionKeyData{}
	// entries can be nil, we have to check that first!
	for i, val := range entry {
		if s, ok := val.(string); !ok {
			return nil, errors.New("Weird value stored in redis - this should not happen!")
		} else {
			switch i {
			case 0:
				// try to convert user to type
				if user, userErr := handler.ConvertUser(s); userErr != nil {
					return nil, userErr
				} else {
					result.User = user
				}

			case 1:
				if creation, creationErr := time.Parse("2006-01-02 15:04:05", s); creationErr != nil {
					return nil, creationErr
				} else {
					result.CreationTime = creation
				}

			case 2:
				if valid, validErr := time.Parse("2006-01-02 15:04:05", s); validErr != nil {
					return nil, validErr
				} else {
					result.ValidUntil = valid
				}
			}
		}
	}
	// once here everything is fine
	return result, nil
}

func (handler *RedisSessionHandler) DeleteKey(key string) error {
	return handler.Client.Del(handler.SessionPrefix + key).Err()
}

func (handler *RedisSessionHandler) DeleteEntriesForUser(user UserKeyType) (int64, error) {
	return handler.delUserKeys(fmt.Sprintf("%s%v", handler.UserPrefix, user), true)
}

func (handler *RedisSessionHandler) DeleteInvalidKeys() (int64, error) {
	return 0, nil
}

// Users stuff

type RedisUserHandler struct {
	Client    *redis.Client
	PwHandler PasswordHandler

	UserPrefix, NextIDKey string
}

func NewRedisUserHandler(client *redis.Client, pwHandler PasswordHandler) *RedisUserHandler {
	if pwHandler == nil {
		pwHandler = DefaultPWHandler
	}
	return &RedisUserHandler{Client: client, PwHandler: pwHandler, UserPrefix: "user:"}
}

func (handler *RedisUserHandler) Init() error {
	return nil
}

func (handler *RedisUserHandler) Insert(userName, firstName, lastName, email string, plainPW []byte) (uint64, error) {
	// encrypt password
	encrypted, encErr := handler.PwHandler.GenerateHash(plainPW)
	if encErr != nil {
		return NoUserID, encErr
	}
	userkey := fmt.Sprintf("%s%v", handler.UserPrefix, userName)
	// check if user already exists
	if exists, existsErr := handler.Client.Exists(userkey).Result(); existsErr != nil {
		return NoUserID, existsErr
	} else if exists > 0 {
		// user already exists
		return NoUserID, errors.New("Username already in use")
	}
	// get next id
	id, idErr := handler.Client.Incr(handler.NextIDKey).Result()
	if idErr != nil {
		return NoUserID, idErr
	}
	// insert
	insertErr := handler.Client.HMSet(userkey, map[string]interface{}{
		"id":        id,
		"username":  userName,
		"firstName": firstName,
		"lastName":  lastName,
		"email":     email,
		"password":  string(encrypted),
	}).Err()
	if insertErr != nil {
		return NoUserID, insertErr
	}
	// success
	return uint64(id), nil
}

func (handler *RedisUserHandler) Validate(userName string, cleartextPwCheck []byte) (uint64, error) {
	// try to get the entry
	userkey := fmt.Sprintf("%s%v", handler.UserPrefix, userName)
	entry, getErr := handler.Client.HMGet(userkey, "id", "password").Result()
	if getErr != nil {
		return NoUserID, getErr
	}
	if entry[0] == nil {
		// not found
		return NoUserID, ErrUserNotFound
	}
	idStr, idOk := entry[0].(string)
	if !idOk {
		return NoUserID, errors.New("Weird type in redis, should not happen")
	}
	pwStr, pwOk := entry[1].(string)
	if !pwOk {
		return NoUserID, errors.New("Weird type in redis, should not happen")
	}
	test, testErr := handler.PwHandler.CheckPassword([]byte(pwStr), cleartextPwCheck)
	if testErr != nil {
		return NoUserID, testErr
	}
	if test {
		// parse entry
		id, parseErr := strconv.ParseUint(idStr, 10, 64)
		if parseErr != nil {
			return NoUserID, parseErr
		}
		return id, nil
	} else {
		return NoUserID, nil
	}
}

func (handler *RedisUserHandler) UpdatePassword(userName string, plainPW []byte) error {
	// try to encrypt the pw
	encrypted, encErr := handler.PwHandler.GenerateHash(plainPW)
	if encErr != nil {
		return encErr
	}
	// try to get the entry
	userkey := fmt.Sprintf("%s%v", handler.UserPrefix, userName)
	exists, existsErr := handler.Client.Exists(userkey).Result()
	if existsErr != nil {
		return existsErr
	} else if exists == 0 {
		return ErrUserNotFound
	}
	// update
	updateErr := handler.Client.HMSet(userkey, map[string]interface{}{
		"password": string(encrypted),
	}).Err()
	return updateErr
}
