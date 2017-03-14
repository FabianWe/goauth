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
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// An interface that knows to methods:
// - Create a has from a given (plaintext) password
// - Compare a previously by this method generated hash and compare it to
//   another password.
// There is an implementation BcryptHandler, so you don't have to write one
// on your own, but you could!
type PasswordHandler interface {
	// Generate a password hash from the given password.
	GenerateHash(password []byte) ([]byte, error)

	// Check if the passwords are equal, can return an error (something is
	// wrong with the data). This should still be handled as failure but you
	// may wish to preceed differently
	CheckPassword(hashedPW, password []byte) (bool, error)
}

// The default cost parameter for bcrypt.
const DefaultCost = 10

// A PasswordHandler that uses bcrypt.
type BcryptHandler struct {
	cost int
}

// Create a new PasswordHandler that uses bcrypt.
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

func (handler *BcryptHandler) GenerateHash(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, handler.cost)
}

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

// Generate a random byte slice of size n.
func RandomBytes(n int) ([]byte, error) {
	res := make([]byte, n)
	if _, err := rand.Read(res); err != nil {
		return nil, err
	}
	return res, nil
}

// Create a random string that is the base64 encoding of a byte slice of
// size n. This encoding is URL safe. Note that n specifies the size of
// the byte slice, the base64 encoding has a different length!
func RandomBase64(n int) (string, error) {
	b, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// An interface for types that can generate a session key.
// A session key is a string (usually base64). It should have reasonable length.
// The length of the session keys should be fixed!
// You can use the RandomBase64 function to create a random string.
// For example use 48 bytes for a base64 of length 64 or 96 bytes for length 128.
// We use a length of 128, so 96 bytes per default.
type SessionKeyGenerator interface {
	GenerateSessionKey() (string, error)
}

type DefaultSessionKeyGenerator struct{}

func NewDefaultSessionKeyGenerator() DefaultSessionKeyGenerator {
	return DefaultSessionKeyGenerator{}
}

func (gen DefaultSessionKeyGenerator) GenerateSessionKey() (string, error) {
	return RandomBase64(96)
}

//////// SQL ////////

// In each database schema there should be a value that uniquely identifies the
// user. This could be some sort of int, a uuuid string or something completely
// different. We allow everything, but you must make sure that you always
// use the same type as user identifiaction and that it can be compared in SQL
// with the = operator.
type UserIDType interface{}

type MYSQLConnector struct {
	sessionGen      SessionKeyGenerator
	activeUserQuery string
}

func NewMYSQLConnector(sessionGen SessionKeyGenerator, activeUserQuery string) *MYSQLConnector {
	if sessionGen == nil {
		sessionGen = NewDefaultSessionKeyGenerator()
	}
	if activeUserQuery == "" {
		activeUserQuery = "SELECT id, password FROM users WHERE username = ?"
	}
	return &MYSQLConnector{sessionGen: sessionGen, activeUserQuery: activeUserQuery}
}

func (connector *MYSQLConnector) InitSessionKeysTable(db *sql.DB, sqlUserKeyType string, keyLength int) error {
	if sqlUserKeyType == "" {
		sqlUserKeyType = "BIGINT UNSIGNED NOT NULL"
	}
	if keyLength <= 0 {
		keyLength = 128
	}
	stmt := `
	CREATE TABLE IF NOT EXISTS user_sessions (
		user_id %s,
		session_key CHAR(%d),
		login_time TIME,
		last_seen TIME,
		UNIQUE(session_key)
	);`
	stmt = fmt.Sprintf(stmt, sqlUserKeyType, keyLength)
	_, err := db.Exec(stmt)
	return err
}

func (connector *MYSQLConnector) GenSession(db *sql.DB, userID UserIDType) (string, error) {
	// first get the current time and convert it to UTC
	now := time.Now().UTC()
	// now create a new session key
	key, genError := connector.sessionGen.GenerateSessionKey()
	if genError != nil {
		return "", genError
	}
	// insert into database
	stmt := "INSERT INTO user_sessions(user_id, session_key, login_time, last_seen) VALUES(?, ?, ?, ?)"
	_, execErr := db.Exec(stmt, userID, key, now, now)
	if execErr != nil {
		return "", execErr
	}
	return key, nil
}

// TODO add function to remove all key given a user id!

func bla() {

}
