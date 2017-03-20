*A major restructure is going in, don't you just yet, this documentation is outdated*

# goauth
Package goauth provides convinient functions to authenticate users, encrypt their passwords and create and check login sessions (via tokens).

The documentation of this package can be found on [GoDoc](https://godoc.org/github.com/FabianWe/goauth%20GoDoc).

License: [MIT License](https://opensource.org/licenses/MIT)

# What is this package for
This package may help you if:

 - You wish to manage user sessions: A user logs in and stays logged in until his login session expires. This package creates a database (at the moment only MySQL is supported) and stores session keys in it. It helps you with the generation and validation of such keys. You can store them in a secure cookie for example.
 - Manage user accounts in a database: There are different ways to accomplish this, either by using a default scheme that is defined in this package our with your own scheme. This package takes care that user passwords are stored in a secure way using [bcrypt](https://godoc.org/github.com/FabianWe/goauth "bcrypt").

I wanted to develop some small Go web applications without a big framework or something like that but with user authentication and couldn't find a suitable and small library. So I've written this one by myself.

# Quickstart
## Installation
Installation with `go get github.com/FabianWe/goauth/` should do the trick. One important notice though: The [bcrypt](https://godoc.org/github.com/FabianWe/goauth "bcrypt") package still uses the old "golang.org/x/net/context" package. I tried to install it inside a docker container (so a "fresh" installation of Go) and it didn't work because the import can't be resolved in newer versions of Go. I tried even `go tool fix -force context /go/src/golang.org/x/crypto/` (here is the problem). But the acme package uses a package from context that go fix can't fix... So in my docker installation I ended up simply removing the file (see [Dockerfile](./Dockerfile)). Of course this is not a suitable option. So you may have to install the old context package by checking out the project our something. I hope this issue resolves itself once the old imports are gone.

If you're planning to you *sqlite* (support for that should be out very soon) take care of the installation notice, I quote:
"This package can be installed with the go get command

    go get github.com/mattn/go-sqlite3

go-sqlite3 is cgo package. If you want to build your app using go-sqlite3, you need gcc. However, if you install go-sqlite3 with go install github.com/mattn/go-sqlite3, you don't need gcc to build your app anymore."

## Where do I start?
Well, that depends on what you wish to do. First create a mysql database connection using [github.com/go-sql-driver/mysql](github.com/go-sql-driver/mysql) or any other driver that works with MySQL.

After that you only have to create a [SQLConnector](https://godoc.org/github.com/FabianWe/goauth#SQLConnector). Such a connector is used for all kind of interactions between you and the library. It can be created with four arguments, we don't go into the details here (see below) simply use
```go
c := goauth.NewMySQLConnector(db, nil, nil, "")
```
To create it with default values.

### Managing Session Tokens
After you have your database connection, lets call it `db` from now on, you can initialize your sessions database with `InitSessionKeysTable`:
```go
err := c.InitSessionKeysTable("", -1)
```
Again we use some default values, I will discuss the details later. But this command does work and will get you something to work with.
Now you can start to generate new sessions for your users with `GenSession`:
```go
sessionKey, err := c.GenSession(3)
```
The argument is just the key for the user in your user database (or wherever you get that value from). It returns a new session key with suitable length that you can stuff for example into a secure cookie. By default this method returns a key of length 128.

You can check if a session key is still valid with the `IsValidSession` method like this:
```go
validDuration, _ := time.ParseDuration("168h")
id, err := c.IsValidSession(validDuration, sessionKey, true)
```
This method has three arguments:

 1. validDuration: A [time.Duration](https://godoc.org/time#Duration) instance that defines how long a session key is considered valid. For each session key we store in the database the time when the key was created, we add the duration and check if this is before now. If yes the session key is considered valid (and of course it must exist in the database).
 2. sessionKey: The key you want to check, for example a user sent it to you in a cookie.
 3. forceUint64: This is maybe a really strange argument but I wanted it to be there. If true the returned id is forced to be of type `uint64`. The reason will be explained below.

This method also updates the `last_seen` column to the current date.

That's it, you can now create sessions for your users (by passing the id of the user) and check if a session key is still valid (retrieve the userid from IsValidSession).
Now I'll get you into some details of the method we used above. The [NewMYSQLConnector](https://godoc.org/github.com/FabianWe/goauth#NewMYSQLConnector) method accepts as first argument a the database you want to use. Then a [SessionKeyGenerator](https://godoc.org/github.com/FabianWe/goauth#SessionKeyGenerator). This is an interface type that generates new session keys. You can specify your own our use the default one that produces 128 length base64 strings (by setting it to nil, as we did).

The `InitSessionKeysTable` function required two arguments:

 1. `sqlUserKeyType` of type `string`. That determines which key type should be used to identify a user in the key table. For example you could use an auto incremented int in MySQL or some other type like string as primary key. Whatever you use this string must be set to the SQL type to store this information. It defaults to `BIGINT UNSIGNED NOT NULL` . You can change that behaviour to your needs.
 2. `keyLength` of type `int`. As mentioned before the session keys are of fixed length. Therefore we store them as `CHAR(keyLength)` in SQL. It defaults to 128 (if <= 0), the length our default generator creates.

So cosumizing the database according to your needs is easy: Set the key type to the SQL type that holds your user keys and set key length to the length of the keys generated with your `SessionKeyGenerator`.
And now we understand the argument that was passed to `GenSession`: It is the key of the user you create this key for. This value is of the type
```go
type UserIDType interface{}
```
So that you can pass every kind of key to it. A note: when retrieving the key a pointer to an `interface{}` is passed to the sql [Scan](https://golang.org/pkg/database/sql/#Row.Scan) method. Your database driver in this case assignes a type to it. That's why I added the argument `forceUint64` to the method: Usually SQL ids are bit unsigned integers but the mysql driver converts it to an `int64`.  With this method I ensure that the underlying value is certainly of type `uint64`.

### Session Keys: Final Words
The `GenSession` function adds an entry to the sessions table even if there is already a session key for that user. For example if a user logs in on multiple devices he/she can have a valid key on each one. If you don't want this behaviour you should write your own method to control this stuff. The database scheme for sessions is rather straight forward:

```mysql
CREATE TABLE IF NOT EXISTS user_sessions (
	user_id %s,
	session_key CHAR(%d),
	login_time DATETIME NOT NULL,
	last_seen DATETIME NOT NULL,
	UNIQUE(session_key)
);`
```
Where `%s` and `%d` are replaced by your id type / key length. You can also call the function `InitSessionKeysTable` multiple times (for example at each start of your application). The table will be created only if it does not exist.

You should also take care to remove entries from the table that are no longer valid, otherwise you always store old session keys. Do this regularly. There are some methods to help you with this: `CleanSessions` and `CleanSessionsDaemon`. Or you could easily write a small executable to run in a cronjob.

### Managing User Authentication
Of course you should **never** store any password in plaintext our with an insecure hash such as MD5. You want something more secure that is harder to crack. By default all passwords get encrypted with bcrypt.
To get started: You can initialize a default user table with the `InitDefaultUserScheme` function:
```go
type SessionKeyGenerator interface {
err := c.InitDefaultUserScheme(-1)
}
```
This sets some default parameters and creates a table of the following form:
```mysql
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
```
Where `%d` gets replaced by your password length. The default is 60, which is the length of the hash returned by bcrypt. If you don't want this style simply create your own PasswordHandler and set the length accordingly. If you want to keep the rest of the functionality only make sure id, username and password look nearly as here.

If you use this basic scheme you can add a new user with the `InsertDefaultUserScheme` function:
```go
sqlRes, err := InsertDefaultUserScheme(username,
    firstName, lastName, email, []byte("some password"))  
```

There are two ways to authenticate a user: Using some table that looks like the default scheme and one for everybody else.

If you use the default scheme you can use something like:
```go
userId, passwordCheck, err := c.CheckDefaultUserPassword(username, []byte("check password"))
```
See the function documentation on [godoc](https://godoc.org/github.com/FabianWe/goauth) for details.
This also works for any other scheme as long as it has an id field of type `BIG INT UNSIGNED` (also other int type should work), a username field of a string type and a field password of a string type. username must be unique in that table in this case!
Note that this function only checks the password: It ignores the `is_active` (if you have something like this in your table).

If you use another database scheme you can pass a query to `NewMYSQLConnector` (the third argument). This query looks like this by default:
```mysql
SELECT password FROM users WHERE id = ?
```
If you set the query to `""` this query will be used. Otherwise simply replace it by a query that has one ? in it to be replaced by your user id and selects only the password of that user.

With this done you can  use `CheckUserPassword` like this:
```go
passwordCheck, err := c.CheckUserPassword(userId, []byte("some password))
```
This will then execute the query you defined in `NewMYSQLConnector` and check if the password is valid.
In any case you should read the [documentation](https://godoc.org/github.com/FabianWe/goauth) first. 

## Implementing your own SessionKeyGenerator
The [SessionKeyGenerator](https://godoc.org/github.com/FabianWe/goauth#SessionKeyGenerator) interface is pretty simple:
```go
type SessionKeyGenerator interface {
	GenerateSessionKey() (string, error)
}
```
The method `GenerateSessionKey` must return a fixed-sized random string. Usually this is the base64 encoding of a random byte array. The package provides you with methods that help you to do this: [RandomBytes](https://godoc.org/github.com/FabianWe/goauth#RandomBytes) and [RandomBase64](https://godoc.org/github.com/FabianWe/goauth#RandomBase64). Of course you can do whatever you like, just make it absolutely random.

Also make sure to adjust the `keyLength` parameter in `InitSessionKeysTable`.

## Implementing your own PasswordHandler
The [PasswordHandler](https://godoc.org/github.com/FabianWe/goauth#PasswordHandler) interface looks like this:
```go
type PasswordHandler interface {
	GenerateHash(password []byte) ([]byte, error)
	CheckPassword(hashedPW, password []byte) (bool, error)
}
```
You should take care that you use a secure function for that! bcrypt should be good. Also make sure that the hash this method returns is always of the same length. Of course you must adopt your password length in the user database accordingly.

## General Workflow and Some Last Words
Your workflow usually is something like this:

 1. When you get a session key, for example via cookie, hit the sessions database, if the key is valid the user is logged in.
 2. Otherwise redirect user to login page.
 3. If a user logs in generate a new session key and stuff it in a secure cookie.
 
 But this workflow may vary. If you use the default theme you can use the function `LoginDefaultUser` for some support.

When a user is delete / the active flag set to false you should also remove all keys of that user, you can use  `RemoveSessionForUser` for that. Also when the password for a user gets change you should invalid all current keys of the user by removing them.

Also if you detect any form of malicious behaviour on your server you should drop the table `user_sessions`. There is also a function `DropSessionsTable`  that simply uses `DROP TABLE IF EXISTS user_sessions`.

### Session Key Lifespan Behaviour
You might have noticed that in this default behaviour a session key at some time becomes invalid. I personally don't like the idea  of a session that restores itself again and again very much. However you might want exactly that. The idea was that `last_login` refers to the time a user really logged in, I mean via a webform or something and was not automatically assumed to be logged in by using this key. But you can also use `UpdateSessionKey`.

There is also a function `IsValidSessionLastSeen`. This works exactly as `IsValidSession` but compares the `last_seen` field with the duration given the current time rather than `last_login`. It also updates the `last_seen` field on success, so whenever the user is accepted via a "login via key" he/she automatically extends the session key life span. But note that the `CleanSessions` stuff still uses `last_login`! So by this you can let a user authenticate via key again and again but set an upper limit when you absolutely want to destroy a key. You could also use `UpdateSessionKey` from time to time to generate a new session key if you want to issue a new one from time to time. Note that this method updates `last_login` though!

Anyway, we're talking about very important stuff here! So be sure to read the [documentation](https://godoc.org/github.com/FabianWe/goauth) properly before you trust on something!

I hope this library helps you and I like some feedback!

I've just shown you how to do stuff with MySQL, but I'm working on other implementations (at least sqlite and PostgreSQL). It should be very easy to change the database, simply don't use  `MySQLConnector` but another one. Everything is stuffed in interfaces, so just check out the source code documentation!

## Some Copyright Notices
This library uses the go-sql-driver/mysql driver (unchanged) licensed under the [Mozilla Public License Version 2.0](https://www.mozilla.org/en-US/MPL/2.0/), the source code can be found [here](https://github.com/go-sql-driver/mysql).

It also uses bcrypt for golang, the source and license information ca be found [here](https://github.com/golang/crypto).

