package main

import (
	"context"

	// Attempts to increase the OS file descriptors - Fail silently
	"github.com/cyberheb/gojeksf/pkg/runner"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/gologger"
)

func main() {
	// Parse the command line flags and read config files
	options := runner.ParseOptions()

	newRunner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatalf("Could not create runner: %s\n", err)
	}

	err = newRunner.RunEnumeration(context.Background())
	if err != nil {
		gologger.Fatalf("Could not run enumeration: %s\n", err)
	}
}
