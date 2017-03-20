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
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// General SQL implementation with interfaces, MySQL etc. below.
type SQLSessionTemplate interface {
	InitQ() string
	GetQ() string
	CreateQ() string
	DeleteForUserQ() string
	DeleteInvalidQ() string
	DeleteKeyQ() string
	TimeFromScanType(val interface{}) (time.Time, error)
}

type SQLSessionHandler struct {
	DB                                                               *sql.DB
	InitQ, GetQ, CreateQ, DeleteForUserQ, DeleteInvalidQ, DeleteKeyQ string
	TableName                                                        string
	UserIDType                                                       string
	KeySize                                                          int
	TimeFromScanType                                                 func(val interface{}) (time.Time, error)
	ForceUIDuint                                                     bool
}

func NewSQLSessionHandler(db *sql.DB, t SQLSessionTemplate) *SQLSessionHandler {
	// I'm not so happy with this many lines of code, but I don't want to use
	// the reflect package or something either...
	c := SQLSessionHandler{DB: db, TableName: "user_sessions",
		UserIDType: "BIGINT UNSIGNED NOT NULL", KeySize: DefaultKeyLength,
		TimeFromScanType: t.TimeFromScanType, ForceUIDuint: true}
	c.InitQ = fmt.Sprintf(t.InitQ(), c.TableName, c.UserIDType, c.KeySize)
	c.GetQ = fmt.Sprintf(t.GetQ(), c.TableName)
	c.CreateQ = fmt.Sprintf(t.CreateQ(), c.TableName)
	c.DeleteForUserQ = fmt.Sprintf(t.DeleteForUserQ(), c.TableName)
	c.DeleteInvalidQ = fmt.Sprintf(t.DeleteInvalidQ(), c.TableName)
	c.DeleteKeyQ = fmt.Sprintf(t.DeleteKeyQ(), c.TableName)
	return &c
}

func (c *SQLSessionHandler) Init() error {
	_, err := c.DB.Exec(c.InitQ)
	return err
}

func (c *SQLSessionHandler) GetData(key string) (*SessionKeyData, error) {
	var uid, createdVal, validUntilVal interface{}
	var err error
	row := c.DB.QueryRow(c.GetQ, key)
	if c.ForceUIDuint {
		var uidUint uint64
		err = row.Scan(&uidUint, &createdVal, &validUntilVal)
		uid = uidUint
	} else {
		err = row.Scan(&uid, &createdVal, &validUntilVal)
	}
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, KeyNotFoundErr
		}
		return nil, err
	}
	created, err := c.TimeFromScanType(createdVal)
	if err != nil {
		return nil, err
	}
	validUntil, err := c.TimeFromScanType(validUntilVal)
	if err != nil {
		return nil, err
	}
	// everything ok
	val := SessionKeyData{User: uid, CreationTime: created, ValidUntil: validUntil}
	return &val, nil
}

func (c *SQLSessionHandler) CreateEntry(user UserKeyType, key string, validDuration time.Duration) (*SessionKeyData, error) {
	data := CurrentTimeKeyData(user, validDuration)
	_, err := c.DB.Exec(c.CreateQ, user, key, data.CreationTime, data.ValidUntil)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (c *SQLSessionHandler) DeleteEntriesForUser(user UserKeyType) (int64, error) {
	res, err := c.DB.Exec(c.DeleteForUserQ, user)
	if err != nil {
		return -1, err
	}
	num, err := res.RowsAffected()
	if err != nil {
		return -1, nil
	}
	return num, nil
}

func (c *SQLSessionHandler) DeleteInvalidKeys() (int64, error) {
	now := CurrentTime()
	res, err := c.DB.Exec(c.DeleteInvalidQ, now)
	if err != nil {
		return -1, err
	}
	num, err := res.RowsAffected()
	if err != nil {
		return -1, nil
	}
	return num, nil
}

func (c *SQLSessionHandler) DeleteKey(key string) error {
	_, err := c.DB.Exec(c.DeleteKeyQ, key)
	return err
}

type MySQLTemplate struct {
}

func NewMySQLTemplate() MySQLTemplate {
	return MySQLTemplate{}
}

func (t MySQLTemplate) InitQ() string {
	return `CREATE TABLE IF NOT EXISTS %s (
		user_id %s,
		session_key CHAR(%d),
    created DATETIME NOT NULL,
    valid_until DATETIME NOT NULL,
		PRIMARY KEY (session_key)
	);`
}

func (t MySQLTemplate) GetQ() string {
	return "SELECT user_id, created, valid_until FROM %s WHERE session_key = ?;"
}

func (t MySQLTemplate) CreateQ() string {
	return "INSERT INTO %s (user_id, session_key, created, valid_until) VALUES (?, ?, ?, ?);"
}

func (t MySQLTemplate) DeleteForUserQ() string {
	return "DELETE FROM %s WHERE user_id = ?;"
}

func (t MySQLTemplate) DeleteInvalidQ() string {
	return "DELETE FROM %s WHERE valid_until > ?;"
}

func (t MySQLTemplate) DeleteKeyQ() string {
	return "DELETE FROM %s WHERE session_key = ?"
}

func (t MySQLTemplate) TimeFromScanType(val interface{}) (time.Time, error) {
	// first check if we already got a time.Time because parseTime in
	// the MySQL driver is true
	if alreadyTime, ok := val.(time.Time); ok {
		return alreadyTime, nil
	}
	if bytes, ok := val.([]byte); ok {
		s := string(bytes)
		// let's hope this is correct... however who came up with THIS parse
		// function definition in Go?!
		return time.Parse("2006-01-02 15:04:05", s)
	} else {
		// we have to return some time... why not now.
		return time.Now().UTC(), errors.New("Invalid date in database, probably a bug if you end up here.")
	}
}
