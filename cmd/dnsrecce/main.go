package main

import (
	"context"
	"fmt"
	"os"

	"dnsrecce/internal"
)

func main() {
	if err := internal.Execute(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
