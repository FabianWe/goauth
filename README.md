# goauth
Package goauth provides convinient functions to authenticate users, encrypt their passwords and create and check login sessions (via tokens).

The documentation of this package can be found on [GoDoc](https://godoc.org/github.com/FabianWe/goauth).

License: [MIT License](https://opensource.org/licenses/MIT)

# What is this package for
This package may help you if:

 - You wish to manage user sessions: A user logs in and stays logged in until his login session expires. This package creates a database and stores session keys in it. It helps you with the generation and validation of such keys. You can store them in a secure cookie for example. Currently supported for user sessions: MySQL, postgres, sqlite3 and redis.
 - Manage user accounts in a database: There are different ways to accomplish this, either by using a default scheme that is defined in this package our with your own scheme. This package takes care that user passwords are stored in a secure way using [bcrypt](https://godoc.org/golang.org/x/crypto/bcrypt) or with onre more line of code [scrypt](https://godoc.org/golang.org/x/crypto/scrypt). Supported storages: MySQL, postgres, sqlite3 and redis.

I wanted to develop some small Go web applications without a big framework or something like that but with user authentication and couldn't find a suitable and small library. So I've written this one by myself.

## Current Version and Safety
User authentication and session management is very important and needs to be absolutely safe. I've written this package by myself and until now no one revised the code. If someone would do that I would be very happy!

The current release is version v0.3, I haven't really tested it in any project yet, but I'm going to do so. Since this project is just starting yet I'm not tagging it. I will develop in a new branch v0.4 from now on and the master branch stays at version v0.3 for now. But I think there may be some changes I'll have to make once I really use this project, so I will merge v0.3 in the master pretty soon.

Please not that this package comes without any warranty: If you use it do it on your own risk.

# Quickstart
## Installation
Installation with `go get github.com/FabianWe/goauth/` should do the trick. One important notice though: The [bcrypt](https://godoc.org/github.com/FabianWe/goauth "bcrypt") package still uses the old "golang.org/x/net/context" package. I tried to install it inside a docker container (so a "fresh" installation of Go) and it didn't work because the import can't be resolved in newer versions of Go. I tried even `go tool fix -force context /go/src/golang.org/x/crypto/` (here is the problem). But the acme package uses a package from context that go fix can't fix... So in my docker installation I ended up simply removing the file (see [Dockerfile](./Dockerfile)). Of course this is not a suitable option. So you may have to install the old context package by checking out the project our something. I hope this issue resolves itself once the old imports are gone.

If you're planning to you *sqlite* (support for that should be out very soon) take care of the installation notice, I quote:
"This package can be installed with the go get command

    go get github.com/mattn/go-sqlite3

go-sqlite3 is cgo package. If you want to build your app using go-sqlite3, you need gcc. However, if you install go-sqlite3 with go install github.com/mattn/go-sqlite3, you don't need gcc to build your app anymore."

## Where Do I Start?
The [wiki](https://github.com/FabianWe/goauth/wiki) of this project is a good starting point. It explains most of the basics. Also you should read the [
entation](https://godoc.org/github.com/FabianWe/goauth) on GoDoc.

In order to work properly you need a good backend for your storage. There is an in memory implementation for user sessions, but this is not very efficient and also you loose all your data once you stop your program.

You should really use a database, such as MariadDB (or any other MySQL) or postgres. We also support sqlite3, but this is very slow for this stuff and so not a good choice.

One important note: Since we use gorilla sessions you should take care of the advice in their docs: If you aren't using gorilla/mux, you need to wrap your handlers with context.ClearHandler as or else you will leak memory!

For example use

```go
http.ListenAndServe(":8080", context.ClearHandler(http.DefaultServeMux))
```

## Copyright Notices
Please find the copyright information on the [wiki](https://github.com/FabianWe/goauth/wiki/License). goauth is distributed under the [MIT License](https://opensource.org/licenses/MIT). 
