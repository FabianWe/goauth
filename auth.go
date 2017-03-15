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

// Package goauth provides convinient functions to authenticate users,
// encrypt their passwords and create and check login sessions (via tokens).
//
// See the github page for more details: https://github.com/FabianWe/goauth
package goauth

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"golang.org/x/crypto/bcrypt"
)

/*
PasswordHandler is an interface that knows two methods:

Create a hash from a given (plaintext) password

Compare a previously by this method generated hash and compare it to
another password.

There is an implementation BcryptHandler, so you don't have to write one
on your own, but you could!
*/
type PasswordHandler interface {
	// GenerateHash generates a hash from the given password.
	GenerateHash(password []byte) ([]byte, error)

	// CheckPassword tests if the passwords are equal, can return an error
	// (something is wrong with the data, random engine...). This should still
	// be handled as failure but you may wish to preceed differently.
	CheckPassword(hashedPW, password []byte) (bool, error)
}

// DefaultCost is the default cost parameter for bcrypt.
const DefaultCost = 10

// DefaultPWLength is he default length of encrypted passwords.
// This is 60 for bcrypt.
const DefaultPWLength = 60

// BcryptHandler is a PasswordHandler that uses bcrypt.
type BcryptHandler struct {
	cost int
}

// NewBcryptHandler creates a new PasswordHandler that uses bcrypt.
// cost is the cost parameter for the algorithm, use -1 for the default value
// (which should be fine in most cases). The default value is 10.
// Note that bcrypt has some further restrictions on the cost parameter:
// Currently it must be between 4 and 31.
func NewBcryptHandler(cost int) *BcryptHandler {
	if cost <= 0 {
		cost = DefaultCost
	}
	return &BcryptHandler{cost: cost}
}

// GenerateHash generates the password hash using bcrypt.
func (handler *BcryptHandler) GenerateHash(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, handler.cost)
}

// CheckPassword checks if the plaintext password was used to create the
// hashedPW.
func (handler *BcryptHandler) CheckPassword(hashedPW, password []byte) (bool, error) {
	// get error from bcrypt
	err := bcrypt.CompareHashAndPassword(hashedPW, password)
	// Check what the error was, if it is nil everything is ok
	if err == nil {
		return true, nil
	}
	// if it is ErrMismatchedHashAndPassword no real error occurred, pws simply
	// didn't match
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	// otherwise something really went wrong
	return false, err
}

// RandomBytes generates a random byte slice of size n.
func RandomBytes(n int) ([]byte, error) {
	res := make([]byte, n)
	if _, err := rand.Read(res); err != nil {
		return nil, err
	}
	return res, nil
}

// RandomBase64 creates a random string that is the base64 encoding of a byte
// slice of size n. This encoding is URL safe. Note that n specifies the size of
// the byte slice, the base64 encoding has a different length!
func RandomBase64(n int) (string, error) {
	b, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// SessionKeyGenerator is an interface for types that can generate a session key.
// A session key is a string (usually base64). It should have reasonable length.
// The length of the session keys should be fixed!
// You can use the RandomBase64 function to create a random string.
// For example use 48 bytes for a base64 of length 64 or 96 bytes for length 128.
// We use a length of 128, so 96 bytes per default.
type SessionKeyGenerator interface {
	GenerateSessionKey() (string, error)
}

// DefaultSessionKeyGenerator is an implementation of SessionKeyGenerator that
// produces random base64 strings of size 128.
type DefaultSessionKeyGenerator struct{}

// NewDefaultSessionKeyGenerator creates a new generator.
func NewDefaultSessionKeyGenerator() DefaultSessionKeyGenerator {
	return DefaultSessionKeyGenerator{}
}

// GenerateSessionKey generates a base64 random string of length 128.
func (gen DefaultSessionKeyGenerator) GenerateSessionKey() (string, error) {
	return RandomBase64(96)
}

//////// DATABASE ////////

// UserIDType A type for identifiying a user uniquely in the database.
// In each database schema there should be a value that uniquely identifies the
// user. This could be some sort of int, a uuuid string or something completely
// different. We allow everything, but you must make sure that you always
// use the same type for user identifiaction and that it can be compared in SQL
// with the = operator.
type UserIDType interface{}

// This interface is used as a base for all sql connections.
// It must return the appropriate query for several tasks.
// The documentation specifies some example of how the query might look like
// in MYSQL syntax so you get a better understanding of what is intended.
// Ensure that your ? replace parameters are present in the right order!
// That's why I've included the example queries.
type SQLSessionQueries interface {
	// InitTableQ returns a query to initalise a table called "user_sessions".
	// See further documentation for the layout.
	// This method must create the table only if it does not already exist.
	InitTableQ(sqlUserKeyType string, keyLength int) string

	// GenSessionQ returns a query that is used to create a new entry in the
	// All for arguments for this table must be contained as ?
	// Example: "INSERT INTO user_sessions(user_id, session_key, login_time, last_seen) VALUES(?, ?, ?, ?)"
	GenSessionQ() string

	// UpdateSessionsQ returns a query that is used to update the user_sessions
	// table. It gets a session key used for lookup in the database and
	// updates session_key and login_time, so the query should look like this:
	// "UPDATE user_sessions SET session_key = ?, login_time = ? WHERE session_key = ?"
	UpdateSessionsQ() string

	// GetUserAndTimeByKeyQ query must select the user_id and the time by the
	// defined in the column columnname where the provided session_key
	// matches the given key.
	// So you should to do the following: Get the user_id and the time
	// as defined in the columntable where session_key = ?
	// So the columnname is one of the two time information we store:
	// It is either "last_login" or "last_seen" and you should format it inside.
	// Example: "SELECT user_id, %s FROM user_sessions WHERE session_key = ?"
	// and them format with columnname
	GetUserAndTimeByKeyQ(columnname string) string

	// UpdateLastSeenQ returns a query that updates the last_seen field
	// in the user_sessions table.
	// Example: "UPDATE user_sessions SET last_seen=? WHERE session_key = ?"
	UpdateLastSeenQ() string

	// CleanSessesionsQ returns a query that must remove all rows from the
	// user_sessions table where the login time is <= some predefined value
	// Example: "DELETE FROM user_sessions WHERE login_time <= ?"
	CleanSessesionsQ() string

	// RemoveSessionForUserIDQ returns a query that must remove all rows from
	// user_sessions where the user_id equals some predefined value.
	// Example: "DELETE FROM user_sessions WHERE user_id = ?"
	RemoveSessionForUserIDQ() string

	// DropTableQ returns a query that must completely remove the user_sessions
	// table. That should only happen if the table indeed exists.
	// Example: "DROP TABLE IF EXISTS user_sessions"
	DropTableQ() string

	// TimeFromScanType is a handler that fixes problems with time.Time.
	// This method may seem a bit weird to you, and it is.
	// The time type causes some problems on databases.
	// For example the MySQL driver processes them as strings
	// (more specific []byte), only with the NullTime type from the driver
	// is it avoidable (or with a global option we must force the user
	// to use).
	// I don't want to include the driver anyway and different drivers may
	// handle time differently. For this purpose there is this method:
	// Deal with whatever your driver returns and for DATETIME and correctly
	// convert it to a time.Time.
	// However, again a problem with the MySQL driver: If the parseTime
	// option is indeed set to true we handle this in the method
	// by checking the type. Ugly, but it should do.
	// In MySQL for example with accept the fact that we get a string and
	// parse it accordingly in TimeFromScanType.
	TimeFromScanType(val interface{}) (time.Time, error)
}

//////// END DATABASE ////////
