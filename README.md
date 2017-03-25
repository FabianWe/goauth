# goauth
Package goauth provides convinient functions to authenticate users, encrypt their passwords and create and check login sessions (via tokens).

The documentation of this package can be found on [GoDoc](https://godoc.org/github.com/FabianWe/goauth).

License: [MIT License](https://opensource.org/licenses/MIT)

# What is this package for
This package may help you if:

 - You wish to manage user sessions: A user logs in and stays logged in until his login session expires. This package creates a database (at the moment only MySQL is supported) and stores session keys in it. It helps you with the generation and validation of such keys. You can store them in a secure cookie for example.
 - Manage user accounts in a database: There are different ways to accomplish this, either by using a default scheme that is defined in this package our with your own scheme. This package takes care that user passwords are stored in a secure way using [bcrypt](https://godoc.org/github.com/FabianWe/goauth "bcrypt").

I wanted to develop some small Go web applications without a big framework or something like that but with user authentication and couldn't find a suitable and small library. So I've written this one by myself.

## Current Version and Safety
User authentication and session management is very important and needs to be absolutely safe. I've written this package by myself and until now no one revised the code. If someone would do that I would be very happy!

The current release is version 0.1, I haven't really tested it in any project yet, but I'm going to do so. Since this project is just starting yet I'm not tagging it. I will develop in a new branch v0.2 from now on and the master branch stays at version 0.1 for now. But I think there may be some changes I'll have to make once I really use this project, so I will merge v0.2 in the master pretty soon.

Please not that this package comes without any warranty: If you use it do it on your own risk.

# Quickstart
## Installation
Installation with `go get github.com/FabianWe/goauth/` should do the trick. One important notice though: The [bcrypt](https://godoc.org/github.com/FabianWe/goauth "bcrypt") package still uses the old "golang.org/x/net/context" package. I tried to install it inside a docker container (so a "fresh" installation of Go) and it didn't work because the import can't be resolved in newer versions of Go. I tried even `go tool fix -force context /go/src/golang.org/x/crypto/` (here is the problem). But the acme package uses a package from context that go fix can't fix... So in my docker installation I ended up simply removing the file (see [Dockerfile](./Dockerfile)). Of course this is not a suitable option. So you may have to install the old context package by checking out the project our something. I hope this issue resolves itself once the old imports are gone.

If you're planning to you *sqlite* (support for that should be out very soon) take care of the installation notice, I quote:
"This package can be installed with the go get command

    go get github.com/mattn/go-sqlite3

go-sqlite3 is cgo package. If you want to build your app using go-sqlite3, you need gcc. However, if you install go-sqlite3 with go install github.com/mattn/go-sqlite3, you don't need gcc to build your app anymore."

## Where do I start?
The [wiki](https://github.com/FabianWe/goauth/wiki) of this project is a good starting point. It explains most of the basics. Also you should read the [
entation](https://godoc.org/github.com/FabianWe/goauth) on GoDoc.

In order to work properly you need a good backend for your storage. There is an in memory implementation for user sessions, but this is not very efficient and also you loose all your data once you stop your program.

You should really use a database, such as MariadDB (or any other MySQL) or postgres. We also support sqlite3, but this is very slow for this stuff and so not a good choice.

## Some Copyright Notices
goauth is distributed under the [MIT License](https://opensource.org/licenses/MIT) license:

The MIT License (MIT)

Copyright (c) 2017 Fabian Wenzelmann

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

This library uses the go-sql-driver/mysql driver (unchanged) licensed under the [Mozilla Public License Version 2.0](https://www.mozilla.org/en-US/MPL/2.0/), the source code can be found [here](https://github.com/go-sql-driver/mysql).

It also uses bcrypt for golang, the source and license information ca be found [here](https://github.com/golang/crypto).
