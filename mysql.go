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
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// implementation of SQLSessionConnector that uses MySQL
type MySQLQueries struct{}

func NewMySQLQueries() MySQLQueries {
	return MySQLQueries{}
}

func (q MySQLQueries) InitTableQ(sqlUserKeyType string, keyLength int) string {
	stmt := `
	CREATE TABLE IF NOT EXISTS user_sessions (
		user_id %s,
		session_key CHAR(%d),
		login_time DATETIME NOT NULL,
		last_seen DATETIME NOT NULL,
		UNIQUE(session_key)
	);`
	return fmt.Sprintf(stmt, sqlUserKeyType, keyLength)
}

func (q MySQLQueries) GenSessionQ() string {
	return "INSERT INTO user_sessions(user_id, session_key, login_time, last_seen) VALUES(?, ?, ?, ?);"
}

func (q MySQLQueries) UpdateSessionsQ() string {
	return "UPDATE user_sessions SET session_key = ?, login_time = ? WHERE session_key = ?"
}

func (q MySQLQueries) GetUserAndTimeByKeyQ(columnname string) string {
	return fmt.Sprintf("SELECT user_id, %s FROM user_sessions WHERE session_key = ?", columnname)
}

func (q MySQLQueries) UpdateLastSeenQ() string {
	return "UPDATE user_sessions SET last_seen=? WHERE session_key = ?"
}

func (q MySQLQueries) CleanSessesionsQ() string {
	return "DELETE FROM user_sessions WHERE login_time <= ?"
}

func (q MySQLQueries) RemoveSessionForUserIDQ() string {
	return "DELETE FROM user_sessions WHERE user_id = ?"
}

func (q MySQLQueries) DropTableQ() string {
	return "DROP TABLE IF EXISTS user_sessions"
}

func (q MySQLQueries) TimeFromScanType(val interface{}) (time.Time, error) {
	// first check if we already got a time.Time because parseTime in
	// the MySQL driver is true
	if alreadyTime, ok := val.(time.Time); ok {
		return alreadyTime, nil
	}
	// first convert to string, this is what we used in ScanTimeType, so
	// it must work
	s := string(val.([]byte))
	// let's hope this is correct... however who came up with THIS parse
	// function definition in Go?!
	return time.Parse("2006-01-02 15:04:05", s)
}

// SQLConnector is used as an implementation of the user_sessions database.
// It uses the queries provided by a SQLSessionQueries instance.
// It also needs a SessionKeyGenerator to create new session strings.
type SQLConnector struct {
	QueryGen   SQLSessionQueries
	SessionGen SessionKeyGenerator
}

// TODO update
// NewSQLConnector instantiates a new connector that uses MYSQL.
// sessionGen is the generator used to generate new session keys, set it to nil
// if you want to use the default one (which should be pretty good).
//
// The passwordUserQuery is only important if you also want to add user
// functionality to your database. If you wish to do that on your own simply
// ignore it by setting it to the empty string.
//
// IF you wish to use the user administration tools of this library this
// must be the query to get the password from the database.
// If you pass the empty string the default query looks like this:
// "SELECT password FROM users WHERE id = ?"
// So if you which to use a different query make sure:
// - The query uses exactly one ? that gets replaced by the user id
// - It selects only the password
// Note that this statement will be used with QueryRow, so the id must
// be unique. If you have some other scheme the user managing stuff of mysql
// is probably not what you want, you can use the sessions stuff though!
//
// The pwHandler is used to create new passwords, if you wish to use only the
// sessions feature simply set it to nil.
// Also if you wish to use the default BcryptHandler with DefaultCost you can
// set it to nil.
func NewSQLConnector(queryGen SQLSessionQueries, sessionGen SessionKeyGenerator) *SQLConnector {
	if sessionGen == nil {
		sessionGen = NewDefaultSessionKeyGenerator()
	}
	return &SQLConnector{QueryGen: queryGen, SessionGen: sessionGen}
}

/*
InitSessionKeysTable: Initialise the session keys table.
You can call this function multiple times,
the table only gets created if it doesn't exist already.
We store the following information:

user_id:
The value that uniquely identifies your user. See UserIDType for more information

session_key:
A key of fixed length. This library will create those keys
for you, so you can for example stuff them in a secure cookie.

login_time:
The time the user logged in and generated this key. But this
must not be the last time the user logged in your application,
simply the time the key was generated / its lifespan was
increased. Also there can be more than one session key for a
user, for example if he/she logged in on multiple devices.

last_seen:
The last time this session key was used / IsValidSession was
invoked for that key.

Arguments:

db:
The database to execute the command on.

sqlUserKeyType:
The mysql type as a string that you use to identifiy your
users. If set to the empty string ot defaults to "BIGINT UNSIGNED NOT NULL"

keyLength:
The length of the session keys in the database. This must be
a fixed size. It defaults to 128 (because of the DefaultSessionKeyGenerator)
which produces base64 encoded strings of length 128.
Set to -1 to use the default.

In this database the session keys are unique. So you might get an insert
error if you produce the same string twice, but hey, how likely is that with
random strings of length 128?
*/
func (connector *SQLConnector) InitSessionKeysTable(db *sql.DB, sqlUserKeyType string, keyLength int) error {
	if sqlUserKeyType == "" {
		sqlUserKeyType = "BIGINT UNSIGNED NOT NULL"
	}
	if keyLength <= 0 {
		keyLength = 128
	}
	_, err := db.Exec(connector.QueryGen.InitTableQ(sqlUserKeyType, keyLength))
	return err
}

// GenSession generates a new session for the user. This function will create
// and insert a new key to the database, no matter if there already is
// an entry for the user.
// It returns the key and a possible error. If the error is not nil
// it returns always an empty string.
func (connector *SQLConnector) GenSession(db *sql.DB, userID UserIDType) (string, error) {
	// first get the current time and convert it to UTC
	now := time.Now().UTC()
	// now create a new session key
	key, genError := connector.SessionGen.GenerateSessionKey()
	if genError != nil {
		return "", genError
	}
	// insert into database
	stmt := connector.QueryGen.GenSessionQ()
	_, execErr := db.Exec(stmt, userID, key, now, now)
	if execErr != nil {
		return "", execErr
	}
	return key, nil
}

// UpdateSessionKey is a method for your internal usage: It overwrites an
// existing sessionKey with a new key and returns that key.
// It only updates the login_time, and not the last_seen, I don't know WHY
// you invoked this method but it doesn't mean that the user was seen...
func (connector *SQLConnector) UpdateSessionKey(db *sql.DB, sessionKey string) (string, error) {
	now := time.Now().UTC()
	newKey, genError := connector.SessionGen.GenerateSessionKey()
	if genError != nil {
		return "", genError
	}
	// update the key and login time
	stmt := connector.QueryGen.UpdateSessionsQ()
	res, updateErr := db.Exec(stmt, newKey, now, sessionKey)
	if updateErr != nil {
		return "", updateErr
	}
	rowsAffected, dbErr := res.RowsAffected()
	if dbErr != nil {
		return "", dbErr
	}
	if rowsAffected == 0 {
		return "", errors.New("Unable to update session key: old key was not found")
	}
	// everything ok
	return newKey, nil
}

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

You should clean this database from time to time, either by invoking the
clean_sessions command (for example as a cronjob) or by invoking
the function CleanSessions or even by starting the function
CleanSessionsDaemon with "go CleanSessionsDaemon()".

The forceUint64 argument is there if you use BIG INT UNSIGNED as keys.
By default golang reads that as int64 and not as uint64, so we would throw
away half of all possible values... Don't know if you ever manage that many
users but I think it's just systematic.
*/
func (connector *SQLConnector) IsValidSession(db *sql.DB, validDuration time.Duration, checkKey string, forceUint64 bool) (UserIDType, error) {
	return connector.isValidSessionFromColumn(db, validDuration, checkKey, forceUint64, "login_time")
}

// The same as IsValidSession but it check the last seen field instead of the login_time.
func (connector *SQLConnector) IsValidSessionLastSeen(db *sql.DB, validDuration time.Duration, checkKey string, forceUint64 bool) (UserIDType, error) {
	return connector.isValidSessionFromColumn(db, validDuration, checkKey, forceUint64, "last_seen")
}

// The real code for checking a session key, see IsValidSession for more
// details, this one simply uses an additional string column name
// that is either "login_time" or "last_seen".
func (connector *SQLConnector) isValidSessionFromColumn(db *sql.DB, validDuration time.Duration, checkKey string, forceUint64 bool, columnName string) (UserIDType, error) {
	// first of all get the current time
	now := time.Now().UTC()
	// get all entries from the database that satisfy the conditon that:
	// - the key exists
	// - now is before the time the entry was created + the given duration
	query := connector.QueryGen.GetUserAndTimeByKeyQ(columnName)
	row := db.QueryRow(query, checkKey)
	var id interface{}
	// here the really ugly stuff begins...
	var checkTimeHolder interface{}
	var err error
	if forceUint64 {
		var unsignedID uint64
		err = row.Scan(&unsignedID, &checkTimeHolder)
		id = unsignedID
	} else {
		err = row.Scan(&id, &checkTimeHolder)
	}
	if err != nil {
		if err == sql.ErrNoRows {
			// don't report error, just return nil to notify that the key is not valid
			return nil, nil
		} else {
			return nil, err
		}
	}
	checkTime, err := connector.QueryGen.TimeFromScanType(checkTimeHolder)
	if err != nil {
		// we don't process, if this err is not nil something is really broken
		return nil, err
	}
	// we got a result, so now check if the provided session key is still valid
	validUntil := checkTime.Add(validDuration)
	if now.Before(validUntil) {
		// update last seen
		updateStmt := connector.QueryGen.UpdateLastSeenQ()
		_, updateErr := db.Exec(updateStmt, now, checkKey)
		if updateErr != nil {
			return id, updateErr
		} else {
			return id, nil
		}
	}
	return nil, nil
}

// CleanSessions cleans the sessions table from all invalid sessions.
// Invalid means that the login date + validDuration is <= now.
func (connector *SQLConnector) CleanSessions(db *sql.DB, validDuration time.Duration) (sql.Result, error) {
	now := time.Now().UTC()
	lastValidLogin := now.Add(-validDuration)
	stmt := connector.QueryGen.CleanSessesionsQ()
	return db.Exec(stmt, lastValidLogin)
}

// DropSessionsTable deletes the table user_sessions. You should do this
// every time your server security might have been compromised.
func (connector *SQLConnector) DropSessionsTable(db *sql.DB) (sql.Result, error) {
	stmt := connector.QueryGen.DropTableQ()
	return db.Exec(stmt)
}

// MYSQLConnector that can be used to feed information in a MYSQL database.
// It supports password storage and session key generation and administration.
type MYSQLConnector struct {
	SessionGen        SessionKeyGenerator
	PwHandler         PasswordHandler
	PasswordUserQuery string
}

// NewMYSQLConnector instantiates a new connector that uses MYSQL.
// sessionGen is the generator used to generate new session keys, set it to nil
// if you want to use the default one (which should be pretty good).
//
// The passwordUserQuery is only important if you also want to add user
// functionality to your database. If you wish to do that on your own simply
// ignore it by setting it to the empty string.
//
// IF you wish to use the user administration tools of this library this
// must be the query to get the password from the database.
// If you pass the empty string default query looks like this:
// "SELECT password FROM users WHERE id = ?"
// So if you which to use a different query make sure:
// - The query uses exactly one ? that gets replaced by the user id
// - It selects only the password
// Note that this statement will be used with QueryRow, so the id must
// be unique. If you have some other scheme the user managing stuff of mysql
// is probably not what you want, you can use the sessions stuff though!
//
// The pwHandler is used to create new passwords, if you wish to use only the
// sessions feature simply set it to nil.
// Also if you wish to use the default BcryptHandler with DefaultCost you can
// set it to nil.
func NewMYSQLConnector(sessionGen SessionKeyGenerator, pwHandler PasswordHandler, passwordUserQuery string) *MYSQLConnector {
	if sessionGen == nil {
		sessionGen = NewDefaultSessionKeyGenerator()
	}
	if pwHandler == nil {
		pwHandler = NewBcryptHandler(DefaultCost)
	}
	if passwordUserQuery == "" {
		passwordUserQuery = "SELECT password FROM users WHERE id = ?"
	}
	return &MYSQLConnector{SessionGen: sessionGen, PwHandler: pwHandler, PasswordUserQuery: passwordUserQuery}
}

// User stuff

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
string of fixed length, if you use the default stuff the length is 60 (which is
also the value if you swet pwLength <= 0). One important note: I hope by using
this package you have already figured out *never* to store passwords in
plaintext!

is_active:
bool that should be set to true when a user becomes inactive.
You should also set this value to false instead of removing
a user permanently. Notice: All verification methods from this package
ignore the possiblity that a user can be inactive!

last_login:
The last time the user logged in, for example over a web form

If you need a more complex solution feel free to do so.
*/
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

// InsertDefaultUserScheme inserts a user into the default user scheme, see
// InitDefaultUserScheme for more information.
func (connector *MYSQLConnector) InsertDefaultUserScheme(db *sql.DB, username,
	firstName, lastName, email string, plaintextPW []byte) (sql.Result, error) {
	now := time.Now().UTC()

	// encrypt the password
	hash, err := connector.PwHandler.GenerateHash(plaintextPW)
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

// CheckUserPassword checks if plaintextPW is the correct password for the user.
// If the user wasn't found it returns sql.ErrNoRows.
func (connector *MYSQLConnector) CheckUserPassword(db *sql.DB, uid UserIDType, plaintextPW []byte) (bool, error) {
	// First lookup the password using the predefined query
	row := db.QueryRow(connector.PasswordUserQuery, uid)
	var password []byte
	if err := row.Scan(&password); err != nil {
		return false, err
	}
	// now that we got the password we verify it
	ok, err := connector.PwHandler.CheckPassword(password, plaintextPW)
	if err != nil {
		return false, err
	}
	return ok, nil
}

/*
CheckDefaultUserPassword uses the default users scheme to look up the user id
and check the password with only one query.

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
func (connector *MYSQLConnector) CheckDefaultUserPassword(db *sql.DB, username string, plaintextPW []byte) (uint64, bool, error) {
	// do a lookup on the users table
	query := "SELECT id, password FROM users WHERE username = ?"
	row := db.QueryRow(query, username)
	var id uint64
	var password []byte

	if err := row.Scan(&id, &password); err != nil {
		return 0, false, err
	}

	// ok, verify password
	ok, err := connector.PwHandler.CheckPassword(password, plaintextPW)
	if err != nil {
		return 0, false, err
	}
	return id, ok, nil
}

// TODO fix again!
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
// func (connector *MYSQLConnector) LoginDefaultUser(db *sql.DB, uid uint64) (string, error) {
// 	now := time.Now().UTC()
// 	// first update the users table
// 	updateStmt := "UPDATE users SET last_login = ? WHERE id = ?"
// 	res, err := db.Exec(updateStmt, now, uid)
// 	if err != nil {
// 		return "", err
// 	}
// 	rowsAffected, dbErr := res.RowsAffected()
// 	if dbErr != nil {
// 		return "", dbErr
// 	}
// 	if rowsAffected == 0 {
// 		// seems the user doesn't exist...
// 		return "", fmt.Errorf("User with id %d wasn't found.", uid)
// 	}
// 	// update was successful, now just return the new session key
// 	return connector.GenSession(db, uid)
// }
