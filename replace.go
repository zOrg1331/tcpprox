package tcpprox

import (
	"fmt"
	"regexp"
)

func DoReplace(input []byte) []byte {
	orig := "data to replace"

	re, err := regexp.Compile(orig)
	if err != nil {
		fmt.Printf("invalid replace regex: %s\n", err)
		return nil
	}

	repl := []byte("data to insert")

	fmt.Printf("[*] Replacing '%s' with '%s'\n", re.String(), repl)

	return re.ReplaceAll(input, repl)
}
