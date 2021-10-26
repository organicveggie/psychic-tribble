package main

import (
	"os"

	"github.com/apex/log"
	"github.com/apex/log/handlers/text"
	"github.com/organicveggie/psychic-tribble/cmd"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

func main() {
	log.SetHandler(text.New(os.Stderr))
	cmd.Execute()
}
