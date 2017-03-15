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

type DBConnector interface {
	/*
		   InitSessionKeysTable: Initialise the session keys table.
		   You can call this function multiple times, the table only gets created if it doesn't
		   exist already.
		   We store the following information:

		   user_id:
		   The value that uniquely identifies your user. See UserIDType for more information

		   session_key:
		   A key of fixed length. This library will create those keys
		   for you, so you can for example stuff them in a secure cookie.

		   login_time:
		   The time the user logged in and generated this key. But this
		   must not be the last time the user logged in your application,
		   simply the time the key was generated.
			 Also there can be more than one session key for a user, for example if
			 he/she logged in on multiple devices.

		   last_seen:
		   The last time this session key was used / IsValidSession was
		   invoked for that key.

		   Arguments:

		   sqlUserKeyType:
		   The sql type as a string that you use to identifiy your
		   users. In MySQL if set to the empty string ot defaults to
			 "BIGINT UNSIGNED NOT NULL". Any implementation should provide a sensible
			 default value that is used when the empty string is used.

		   keyLength:
		   The length of the session keys in the database. This must be
		   a fixed size. It defaults to 128
			 (because of the DefaultSessionKeyGenerator)
		   which produces base64 encoded strings of length 128.
		   Set to -1 to use the default.

		   In this database the session keys are unique. So you might get an insert
		   error if you produce the same string twice, but hey, how likely is that with
		   random strings of length 128?
	*/
	InitSessionKeysTable(sqlUserKeyType string, keyLength int) error

	// GenSession generates a new session for the user. This function will create
	// and insert a new key to the database, no matter if there already is
	// an entry for the user.
	// It returns the key and a possible error. If the error is not nil
	// it returns always an empty string.
	GenSession(userID UserIDType) (string, error)

	// UpdateSessionKey is a method for your internal usage: It overwrites an
	// existing sessionKey with a new key and returns that key.
	// It only updates the login_time, and not the last_seen, I don't know WHY
	// you invoked this method but it doesn't mean that the user was seen...
	UpdateSessionKey(sessionKey string) (string, error)

	/*
		IsValidSession checks if a session key is valid given a duration that
		describes how long a key should be considered valid.
		Important to notice: can return a valid user AND an error at the same time
		(see below).
		Note that last_seen means "seen with this token", not last login! If you really
		want something like the last time a user logged in you should store this
		information somewhere else.
		IsValidSession checks if the checkKey provided is valid. This means that

		(a) The key exists in the database
		(b) The key is still valid

		How long a key is considered valid can be controlled by the validDuration
		argument.

		It returns the userid that is stored together with the key and nil if the
		key isn't valid any more.
		It also updates the last_seen field of the key.
		An important note: This method can return both a userid != nil AND
		an error != nil. This may happen when the lookup succeeded but somehow
		the update on the database failed.

		You should clean this database from time to time, for example by invoking
		the function CleanSessions or even by starting the function
		CleanSessionsDaemon with "go CleanSessionsDaemon()". Or you create a
		cronjob and write a small executable.

		The forceUint64 argument is there if you use BIG INT UNSIGNED as keys.
		By default golang reads that as int64 and not as uint64, so we would throw
		away half of all possible values... Don't know if you ever manage that many
		users but I think it's just systematic. This may be a problem specific for
		the MySQL driver, so other implementations might ignore this value.
	*/
	IsValidSession(validDuration time.Duration, checkKey string, forceUint64 bool) (UserIDType, error)

	// The same as IsValidSession but it check the last seen field instead of the login_time.
	IsValidSessionLastSeen(validDuration time.Duration, checkKey string, forceUint64 bool) (UserIDType, error)

	// CleanSessions cleans the sessions table from all invalid sessions.
	// Invalid means that the login date + validDuration is <= now.
	CleanSessions(validDuration time.Duration) (int64, error)

	// DropSessionsTable deletes the table user_sessions. You should do this
	// every time your server security might have been compromised.
	DropSessionsTable() error
}

// A helper function that is usefull if you want to implement a DBConnector
// for yourself.
// If you have already looked up a key and got the timestamp you want
// to compare with now given a valid duration (as a time.Duration)
// you can use and should use this method to check if that key is
// still valid.
// This inforces more consistent behaviour between all implementations of
// DBConnector.
// So referenceTime would be either last_login or last_seen.
// This method returns a bool and a time.Time. time.Time is the current time
// you can insert in order to update your last_seen field.
// I only return it s.t. the time we used to check and the time the insert
// takes place are better coordinated. Useless because it's so ms, but anyway.
func CheckSessionFromTime(validDuration time.Duration, referenceTime time.Time) (bool, time.Time) {
	now := time.Now().UTC()
	validUntil := referenceTime.Add(validDuration)
	return now.Before(validUntil), now
}

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

// This interface is used as a base for all sql connections.
// It must return the appropriate query for several tasks.
// The documentation specifies some example of how the query might look like
// in MYSQL syntax so you get a better understanding of what is intended.
// Ensure that your ? replace parameters are present in the right order!
// That's why I've included the example queries.
type SQLUserQueries interface {
	// Query to intialize the users table. You should always create the table
	// only if it does not exist yet.
	// Example: See for yourself, too long to post here.
	// But you have to configure your database s.t. it can store passwords of
	// fixed length (format it into your query).
	InitDefaultUserSchemeQ(pwLength int) string

	// Query to insert a new user into your scheme, here is the MySQL version:
	// "INSERT INTO users (username, first_name, last_name, email, password, is_active, last_login)
	//	VALUES(?, ?, ?, ?, ?, ?, ?);"
	InsertDefaultUserSchemeQ() string

	// Query to get the id and password from the database given the username in
	// one run.
	// Example:
	// "SELECT id, password FROM users WHERE username = ?"
	CheckDefaultUserPasswordQ() string

	// Query to set the last_login field to the current time given user id.
	// Example:
	// "UPDATE users SET last_login = ? WHERE id = ?"
	UpdateLastLoginDefaultUserQ() string
}

type UserDBConnector interface {
	/*
		   InitDefaultUserScheme initialises a user database.
		   In this scheme a user consists of the following information
		   (most of the stuff taken from Django, but not all):

		   id:
		   SERIAL Identifies a user

		   username:
		   string up to 150 characters

		   first_name:
		   string up to 30 characters

		   last_name:
		   string up to 30 characters

		   email:
		   string up to 254 characters

		   password:
		   string of fixed length, if you use the default stuff the length is 60
			 (which is also the value if you swet pwLength <= 0). One important note:
			 I hope by using this package you have already figured out *never* to store
			 passwords in plaintext!

		   is_active:
		   bool that should be set to true when a user becomes inactive.
		   You should also set this value to false instead of removing
		   a user permanently. Notice: All verification methods from this package
		   ignore the possiblity that a user can be inactive!

		   last_login:
		   The last time the user logged in, for example over a web form

		   If you need a more complex solution feel free to do so.
	*/
	InitDefaultUserScheme(pwLength int) error

	// InsertDefaultUserScheme inserts a user into the default user scheme, see
	// InitDefaultUserScheme for more information.
	InsertDefaultUserScheme(username, firstName,
		lastName, email string, plaintextPW []byte) error

	// CheckUserPassword checks if plaintextPW is the correct password for the user.
	// If the user wasn't found it returns sql.ErrNoRows.
	CheckUserPassword(uid UserIDType, plaintextPW []byte) (bool, error)

	/*
		CheckDefaultUserPassword uses the default users scheme to look up the user
		id and check the password with only one query.

		Note: you can also use your own scheme here, as long as it has the entries id
		(type BIG INT UNSIGNED), password (text of fixed length) and username (text).
		Works otherwise the same as CheckUserPassword does.

		The return values are as follows:

		The first one is the user id found, on error this will always be 0

		The second one is true if the verification was successful and false otherwise

		The error is any error that occurred during any of the steps above.

		Note that it's also possible that an id != 0 is returned but the verification
		still has failed! Always check the bool field if you want to check if the
		authentication was successful.
	*/
	CheckDefaultUserPassword(username string, plaintextPW []byte) (uint64, bool, error)

	// LoginDefaultUser logs in a user and generates a new session key (for the
	// default user database).
	//
	// You should call this method every time a user has successfully
	// logged in, i.e. you have checked a session key or verified the
	// password.
	//
	// This method generates a new session key and stores it in the
	// database. It also updates the last_login field in the users table.
	// If the user was not found in the database it returns
	// sql.ErrNoRows.
	//
	// If an error occurred it always returns an empty string.
	// Note that the sessionConnector is usually the same as your user connector.
	// For example the SQLConnector supports both, sessions and users.
	LoginDefaultUser(uid uint64, sessionConnector DBConnector) (string, error)
}

//////// END DATABASE ////////
