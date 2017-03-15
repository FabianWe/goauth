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

// MySQLQueries is an implementation of SQLSessionConnector that uses MySQL.
import (
	"database/sql"
	"fmt"
	"time"
)

// NewMySQLConnector creates a new SQLConnector using MySQL query generator.
func NewMySQLConnector(db *sql.DB, sessionGen SessionKeyGenerator, pwHandler PasswordHandler, passwordUserQuery string) *SQLConnector {
	return NewSQLConnector(db, NewMySQLQueries(), sessionGen, NewMySQLUserQueries(), pwHandler, passwordUserQuery)
}

// An implementation of SQLSessionConnector using MySQL queries.
type MySQLQueries struct{}

// NewMySQLQueries creates a new SQLSessionConnector that uses MySQL.
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

// An implementation of SQLUserQueries using MySQL queries.
type MySQLUserQueries struct{}

// Creates a new MySQLUserQueries instance.
func NewMySQLUserQueries() MySQLUserQueries {
	return MySQLUserQueries{}
}

func (q MySQLUserQueries) InitDefaultUserSchemeQ(pwLength int) string {
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
	return fmt.Sprintf(stmt, pwLength)
}

func (q MySQLUserQueries) InsertDefaultUserSchemeQ() string {
	return `
	INSERT INTO users (username, first_name, last_name, email, password, is_active, last_login)
		VALUES(?,
       ?,
       ?,
       ?,
       ?,
       ?,
       ?);
	`
}

func (q MySQLUserQueries) CheckDefaultUserPasswordQ() string {
	return "SELECT id, password FROM users WHERE username = ?"
}

func (q MySQLUserQueries) UpdateLastLoginDefaultUserQ() string {
	return "UPDATE users SET last_login = ? WHERE id = ?"
}
