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

package manin

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	"github.com/FabianWe/goauth"
)

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		fmt.Println("This program removes all entries from the session key that")
		fmt.Println("are not considered valid any more. Do this by specifying")
		fmt.Println("the database connection information and the duration:")
		printUsage()
		os.Exit(0)
	}
	if len(os.Args) != 3 {
		fmt.Println("Provide exactly 2 arguments!")
		printUsage()
		os.Exit(1)
	}
	dbInfo, durationStr := os.Args[1], os.Args[2]
	db, openErr := sql.Open("mysql", dbInfo)
	if openErr != nil {
		fmt.Println("Error connecting to database:", openErr)
		os.Exit(1)
	}
	duration, durationErr := time.ParseDuration(durationStr)
	if durationErr != nil {
		fmt.Println("Can't parse", durationStr, "as duration:", durationErr)
		os.Exit(1)
	}
	c := goauth.NewMYSQLConnector(nil, nil, "")
	res, deleteErr := c.ClearSessions(db, duration)

	if deleteErr != nil {
		fmt.Println("Can't remove entries from database:", deleteErr)
		os.Exit(1)
	}

	fmt.Printf("Success! ")
	rowsAffected, resErr := res.RowsAffected()

	if resErr != nil {
		fmt.Println("Can't show you the details, but I removed old entries...")
	} else {
		fmt.Printf("Removed %d entries.\n", rowsAffected)
	}
}

func printUsage() {
	fmt.Println("Usage of clear_sessions")
	fmt.Printf("%s <database> <duration>\n", os.Args[0])
	fmt.Println("The database string must be of the form USERNAME:PASSWORD@tcp(HOST:PORT)/DATABASENAME")
	fmt.Println("Duration must be a string representing the duration how long a session key is considered value.")
	fmt.Println("The format for such a duration is the one from go ParseDuration, e.g. \"100h45m\" for 100 hours and 45 minutes")
}
