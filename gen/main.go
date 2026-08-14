package main

import (
	"fmt"
	"os"
)

func main() {
	data, err := os.ReadFile("./tmp/,ver")
	if err != nil {
		// xyzzy
		os.Exit(1)
	}
	fmt.Printf(`
package main

var GitCommit string = %s%s%s

`, "`", data, "`")
}
