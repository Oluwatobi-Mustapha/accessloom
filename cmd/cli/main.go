package main

import (
	"fmt"
	"io"
	"os"

	"github.com/Oluwatobi-Mustapha/identrail/internal/cli"
	"github.com/Oluwatobi-Mustapha/identrail/internal/config"
)

var cliExecute = cli.Execute
var loadConfig = config.Load

func run(args []string, stdout io.Writer) error {
	return cliExecute(loadConfig(), args, stdout)
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
