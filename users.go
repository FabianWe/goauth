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
	"math"

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

	// PasswordHashLength returns the length of the password hash.
	// The hashes should be of the same length in any used scheme, so this method
	// must return of the elements created with GenerateHash.
	// For bcrypt the length is 60.
	PasswordHashLength() int
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

func (handler *BcryptHandler) PasswordHashLength() int {
	return DefaultPWLength
}

const NoUserID = math.MaxUint64

var ErrUserNotFound = errors.New("Username not found")

type UserHandler interface {
	Init() error
	Insert(userName, firstName, lastName, email string, plainPW []byte) (uint64, error)
	Validate(userName string, CleartextPwCheck []byte) (uint64, error)
}
