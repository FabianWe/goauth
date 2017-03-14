# goauth
Package goauth provides convinient functions to authenticate users, encrypt their passwords and create and check login sessions (via tokens).

The documentation of this package can be found on [GoDoc](https://godoc.org/github.com/FabianWe/goauth%20GoDoc).

License: [MIT License](https://opensource.org/licenses/MIT)

# What is this package for
This package may help you if

 - You wish to manage user sessions: A user logs in and stays logged in until his login session expires. This package creates a database (at the moment only MySQL is supported) and stores session keys in it. It helps you with the generation and validation of such keys. You can store them in a secure cookie for example.
 - Manage user accounts in a database: There are different ways to accomplish this, either by using a default scheme that is defined in this package our with your own scheme. This package takes care that user passwords are stored in a secure way using [bcrypt](https://godoc.org/github.com/FabianWe/goauth "bcrypt").

# Quickstart
## Installation
Installation with `go get github.com/FabianWe/goauth/` should do the trick. One important notice though: The [bcrypt](https://godoc.org/github.com/FabianWe/goauth "bcrypt") package still uses the old "golang.org/x/net/context" package. I tried to install it inside a docker container (so a "fresh" installation of Go) and it didn't work because the important can't be resolved in newer versions of go. I tried even `go tool fix -force context /go/src/golang.org/x/crypto/` (here is the problem). But the acme package uses a package from context that go fix can't fix... So in my docker installation I ended up simply removing the file (see [Dockerfile](./Dockerfile)). Of course this is not a suitable option. So you may have to install the old context package by checking out the project our something. I hope this issue resolves itself once the old imports are gone.

## Where do I start?
Well, that depends on what you wish to do. First create a mysql database connection using [github.com/go-sql-driver/mysql](github.com/go-sql-driver/mysql) or any other driver that works with MySQL.

After that you only have to create a [MYSQLConnector](https://godoc.org/github.com/FabianWe/goauth#MYSQLConnector). Such a connector is used for all kind of interactions between you and the library. It can be created with three arguments, we don't go into the details here (see below) simply use
```go
c := goauth.NewMYSQLConnector(nil, nil, "")
```
To create it with default values.

### Managing Session Tokens
After you have your database connection, lets call it `db` from now on, you can initialise your sessions database with [InitSessionKeysTable](https://godoc.org/github.com/FabianWe/goauth#MYSQLConnector.InitSessionKeysTable):
```go
err := c.InitSessionKeysTable(db, "", -1)
```
 Again we use some default values, I will discuss the details later. But this command does work and will get you something to work with.
Now you can start to generate new sessions for your users with [GenSession](https://godoc.org/github.com/FabianWe/goauth#MYSQLConnector.GenSession):
```go
sessionKey, err := c.GenSession(db, 3)
```
The argument is just the key for the user in your user database (or wherever you get that value from). It returns a new sessionKey with suitable length that you can stuff for example into a secure cookie. By default this method returns a key of length 128.

You can check if a sessionKey is still valid with the [IsValidSession](https://godoc.org/github.com/FabianWe/goauth#MYSQLConnector.IsValidSession) method like this:
```go
validDuration, _ := time.ParseDuration("168h")
id, err := c.IsValidSession(db, validDuration, sessionKey, true)
```
This method has three arguments:

 1. validDuration: A [time.Duration](https://godoc.org/time#Duration) instance that defines how long a session key is considered valid. For each session key we store in the database the time when the key was created, we add the duration and check if this is before now. If yes the session key is considered valid.
 2. sessionKey: The key you want to check, for example a user sent it to you in a cookie.
 3. forceUint64: This is maybe a really strange argument but I wanted it to be there. If true the returned id is forced to be of type uint64. The reason will be explained below.

That's it, you can now create sessions for your users (by passing the id of the user) and check if a session key is still valid (retrieve the userid from IsValidSession).
Now I'll get you into some details of the method we used above. The [NewMYSQLConnector](https://godoc.org/github.com/FabianWe/goauth#NewMYSQLConnector) method accepts as first argument a [SessionKeyGenerator](https://godoc.org/github.com/FabianWe/goauth#SessionKeyGenerator). This is an interface type that generates new session keys. You can specify your own our use the default one that produces 128 length base64 strings.

The `InitSessionKeysTable` function required, except from the database to operate on, two additional arguments:

 1. `sqlUserKeyType` of type string. That determines which key type should be used to identify a user in the key table. For example you could use an auto incremented int in MySQL or some other type like string as primary key. Whatever you use this string must be set to the SQL type to store this information. It defaults to `BIGINT UNSIGNED NOT NULL` . You can change that behaviour to your needs.
 2. `keyLength` of type int. As mentioned before the session keys are of fixed length. Therefore we store them as `CHAR(keyLength)` in SQL. It defaults to 128 (if <= 0), the length our default generator creates.

So cosumizing the database according to your needs is easy: Set the key type to the SQL type that holds your user keys and set key length to the length of the keys generated with your `SessionKeyGenerator`.
And now we understand the argument that was passed to `GenSession`: It simply is the key of the user you create this key for. This value is of the type
```go
type UserIDType interface{}
```
So that you can pass every kind of key to it. A last note: when retrieving the key a pointer to an `interface{}` is passed to the sql [Scan](https://golang.org/pkg/database/sql/#Row.Scan) method. Your database driver in this case assignes a type to it. That's why I added the argument `forceUint64` to the method: Usually SQL ids are bit unsigned integers but the mysql driver converts it to an `int64`.  With this method I ensure that the underlying value is certainly of type `uint64`.

## # Session Tokens: Final Words
The [GenSession](https://godoc.org/github.com/FabianWe/goauth#MYSQLConnector.GenSession) function adds an entry to the sessions table even if there is already a session key for that user. For example if a user logs in on multiple devices he/she can have a valid key on each one. If you don't want this behaviour you should write your own method to control this stuff. The database scheme for sessions is rather straight forward:

```mysql
CREATE TABLE IF NOT EXISTS user_sessions (
		user_id %s,
		session_key CHAR(%d),
		login_time DATETIME NOT NULL,
		last_seen DATETIME NOT NULL,
		UNIQUE(session_key)
	);`
}
```
Where %s and %d are replaced by your id type / key length. You can also call the function `InitSessionKeysTable` (for example at each start of your application). The table will be created only if it does not exist.

You should also take care to remove entries from the table that are no longer valid. Do this regularly. There are some methods to help you with this: [CleanSessions](https://godoc.org/github.com/FabianWe/goauth#MYSQLConnector.CleanSessions), [CleanSessionsDaemon](https://godoc.org/github.com/FabianWe/goauth#MYSQLConnector.CleanSessionsDaemon) and a command [clean_sessions](https://godoc.org/github.com/FabianWe/goauth/cmd/clean_sessions) that you can use for example in a cronjob.

## Implementing your own SessionKeyGenerator
The [SessionKeyGenerator](https://godoc.org/github.com/FabianWe/goauth#SessionKeyGenerator) interface is pretty simple:
```go
type SessionKeyGenerator interface {
	GenerateSessionKey() (string, error)
}
```
The method `GenerateSessionKey` must return a fixed-size random string. Usually this is the base64 encoding of a random byte array. The package provides you with methods that help you to do this: [RandomBytes](https://godoc.org/github.com/FabianWe/goauth#RandomBytes) and [RandomBase64](https://godoc.org/github.com/FabianWe/goauth#RandomBase64). Of course you can do whatever you like, just make it absolutely random.

Also make sure to adjust the `keyLength` parameter in [InitSessionKeysTable](https://godoc.org/github.com/FabianWe/goauth#MYSQLConnector.InitSessionKeysTable).
