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
// encrypt their passwords and create and administer login sessions on top
// of gorilla sessions.
//
// What is the problem with gorilla sessions? Nothing, they're good and do
// what they should do. But there is no direct way to connect these sessions
// with user information. Using them directly for user login sessions is not
// good because:
//
//   The client may not cope with the MaxAge and edit the cookie.
//   In this case it will send the cookie again to the server and gorialla
//   will accept it. At least that's what I found out, maybe I did something
//   wrong but I just edited the lifespan of the cookie and gorilla still
//   accepted it.
//
//   There is no connection between a session and a user you might have in
//   your database. For example if you have a "log out everywhere" function
//   four your user or the user changes his password there is no direct way to
//   connect the gorilla session with that user and invalidate all sessions keys.
//   Or if you delete a user: You don't want the user be able to still login
//   with already delivered keys.
//
// This package provides a lot of interfaces to connect gorilla sessions with
// user information. It also provides implementations for these interface
// for MySQL, postgres and sqlite databases.
//
// See the github page for more details: https://github.com/FabianWe/goauth
// and the wiki for some more explanation and small examples:
// https://github.com/FabianWe/goauth/wiki
package goauth
