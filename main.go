package main

import (
	"github.com/organicveggie/psychic-tribble/cmd"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

func main() {
	cmd.Execute()
}
