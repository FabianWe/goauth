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
	"log"
	"time"

	"github.com/go-sql-driver/mysql"
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

// The default length of encrypted passwords. This is 60 for bcrypt.
const DefaultPWLength = 60

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
	pwHandler       PasswordHandler
	activeUserQuery string
}

// Instantiate a new connector that uses MYSQL.
// sessionGen is the generator used to generate new session keys, set it to nil
// if you want to use the default one (which should be pretty good).
// The activeUserQuery is only important if you also want to add user
// functionality to your database. If you wish to do that on your own simply
// ignore it by setting it to the empty string.
//
// IF you wish to use the user administration tools of this library this
// must be the query to get the user id (something, whatever type), that
// uniquely identifies the user and the password.
// If you pass the empty string default query looks like this:
// "SELECT id, password FROM users WHERE username = ? AND is_active == TRUE"
// So if you which to use a different query make sure:
// - The query uses exactly one ? that gets replaced by the user name
// - It returns exactly to values: First the id, then the password
// Note that this statement will be used with QueryRow, so the username must
// be unique. If you have some other scheme the user managing stuff of mysql
// is probably not what you want, you can use the sessions stuff though!
//
// The pwHandler is used to create new passwords, if you wish to use only the
// sessions feature simply set it to nil.
// Also if you wish to use the default BcryptHandler with DefaultCost you can
// set it to nil.
func NewMYSQLConnector(sessionGen SessionKeyGenerator, pwHandler PasswordHandler, activeUserQuery string) *MYSQLConnector {
	if sessionGen == nil {
		sessionGen = NewDefaultSessionKeyGenerator()
	}
	if pwHandler == nil {
		pwHandler = NewBcryptHandler(DefaultCost)
	}
	if activeUserQuery == "" {
		activeUserQuery = "SELECT id, password FROM users WHERE username = ? AND is_active == TRUE"
	}
	return &MYSQLConnector{sessionGen: sessionGen, pwHandler: pwHandler, activeUserQuery: activeUserQuery}
}

// Initialise the session keys table. You can call this function multiple times,
// the table only gets created if it doesn't exist already.
// We store the following information:
// - user_id: The value that uniquely identifies your user. See UserIDType
//            for more information
// - session_key: A key of fixed length. This library will create those keys
//                for you, so you can for example stuff them in a secure cookie.
// - login_time:  The time the user logged in and generated this key. But this
//                must not be the last time the user logged in your application,
//                simply the time the key was generated / its lifespan was
//                increased. Also there can be more than one session key for a
//                user, for example if he/she logged in on multiple devices.
// - last_seen:   The last time this session key was used / IsValidSession was
//                invoked for that key.
// Arguments:
// db The database to execute the command on.
// sqlUserKeyType: The mysql type as a string that you use to identifiy your
//                 users. If set to the empty string ot defaults to "BIGINT UNSIGNED NOT NULL"
// keyLength:      The length of the session keys in the database. This must be
//                 a fixed size. It defaults to 128 (because of the DefaultSessionKeyGenerator)
//                 which produces base64 encoded strings of length 128.
//                 Set to -1 to use the default.
// In this database the session keys are unique. So you might get an insert
// error if you produce the same string twice, but hey, how likely is that with
// random strings of length 128?
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
		login_time DATETIME NOT NULL,
		last_seen DATETIME NOT NULL,
		UNIQUE(session_key)
	);`
	stmt = fmt.Sprintf(stmt, sqlUserKeyType, keyLength)
	_, err := db.Exec(stmt)
	return err
}

// Generate a new session for the user. This function will create and insert
// a new key to the database, no matter if there already is an entry for the
// user.
// It returns the key and a possible error.
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

// Important to notice: can return a valid user AND an error at the same time
// Note that last_seen means "seen with this token", not last login!
// IsValidSession checks if the checkKey provided is valid. This means that
// (a) The key exists in the database
// (b) The key is still valid
// How long a key is considered valid can be controlled by the validDuration
// argument.
//
// It returns the userid that is stored together with the key and nil if the
// key isn't valid any more.
// It also updates the last_seen field of the key.
// An important note: This method can return both a userid != nil AND
// an error != nil. This may happen when the lookup succeeded but somehow
// the update of the user id failed.
//
// You should clean this database from time to time, either by invoking the
// clear_sessions command (for example with a cronjob) or by invoking
// the function ClearSessions or even by starting the function
// ClearSessionsDaemon with "go ClearSessionsDaemon()".
func (connector *MYSQLConnector) IsValidSession(db *sql.DB, validDuration time.Duration, checkKey string) (UserIDType, error) {
	// first of all get the current time
	now := time.Now().UTC()
	// get all entries from the database that satisfy the conditon that:
	// - the key exists
	// - now is before the time the entry was created + the given duration
	query := "SELECT user_id, login_time FROM user_sessions WHERE session_key = ?"
	row := db.QueryRow(query, checkKey)
	var id interface{}
	// var loginTime time.Time
	var loginTime mysql.NullTime
	err := row.Scan(&id, &loginTime)
	if err != nil {
		if err == sql.ErrNoRows {
			// don't report error, just return nil to notify that the key is not valid
			return nil, nil
		} else {
			return nil, err
		}
	}
	// we got a result, so now check if the provided session key is still valid
	validUntil := loginTime.Time.Add(validDuration)
	if now.Before(validUntil) {
		// update last seen
		updateStmt := "UPDATE user_sessions SET last_seen=? WHERE session_key = ?"
		_, updateErr := db.Exec(updateStmt, now, checkKey)
		if updateErr != nil {
			return id, updateErr
		} else {
			return id, nil
		}
	}
	return nil, nil
}

// Clear the sessions table from all invalid sessions.
// Invalid means that the login date + validDuration is <= now.
func (connector *MYSQLConnector) ClearSessions(db *sql.DB, validDuration time.Duration) (sql.Result, error) {
	// TODO Think again if this is correct...
	now := time.Now().UTC()
	lastValidLogin := now.Add(-validDuration)
	stmt := "DELETE FROM user_sessions WHERE login_time <= ?"
	return db.Exec(stmt, lastValidLogin)
}

// A function that starts an infinite loop and clears the session table after
// the duration sleep. Important: This routine never terminates and therefor
// always has a pointer to your database, so maybe you want to call ClearSessions
// by yourself in some other fassion or use the cmd clear_sessions.
func (connector *MYSQLConnector) ClearSessionsDaemon(db *sql.DB, validDuration, sleep time.Duration, printError bool) {
	for {
		_, err := connector.ClearSessions(db, validDuration)
		if printError && err != nil {
			log.Println("Error while clearing session database:", err)
		}
		time.Sleep(sleep)
	}
}

// Remove all sessions for a specific user.
// You should call this method each time a user gets deleted / inactive...
func (connector *MYSQLConnector) RemoveSessionForUser(db *sql.DB, userID UserIDType) error {
	stmt := "DELETE FROM user_sessions WHERE user_id = ?"
	_, err := db.Exec(stmt, userID)
	return err
}

// User stuff

func (connector *MYSQLConnector) InitDefaultUserScheme(db *sql.DB, pwLength int) error {
	if pwLength <= 0 {
		pwLength = DefaultPWLength
	}
	stmt := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL,
		username VARCHAR(150) NOT NULL,
		first_name VARCHAR(30) NOT NULL,
		last_name VARCHAR(30) NOT NULL,
		email VARCHAR(254),
		password CHAR(%d),
		is_active BOOL,
		last_login DATETIME,
		PRIMARY KEY(id),
		UNIQUE(username)
	);
	`
	stmt = fmt.Sprintf(stmt, pwLength)
	_, err := db.Exec(stmt)
	return err
}

func (connector *MYSQLConnector) InsertDefaultUserScheme(db *sql.DB, username,
	firstName, lastName, email string, plaintextPW []byte) (sql.Result, error) {
	now := time.Now().UTC()

	// encrypt the password
	hash, err := connector.pwHandler.GenerateHash(plaintextPW)
	if err != nil {
		return nil, err
	}

	stmt := `
	INSERT INTO users (username, first_name, last_name, email, password, is_active, last_login)
		VALUES(?,
       ?,
       ?,
       ?,
       ?,
       ?,
       ?);
	`
	return db.Exec(stmt, username, firstName, lastName, email, hash, true, now)
}
