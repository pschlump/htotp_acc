package main

import (
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	data, err := ioutil.ReadFile("./tmp/,ver")
	if err != nil {
		// xyzzy
		os.Exit(1)
	}
	fmt.Printf(`
package main

var GitCommit string = %s%s%s

`, "`", data, "`")
}
