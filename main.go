package main

import (
	"flag"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/travelaudience/kubernetes-vault-client/pkg/config"
)

const (
	defaultPathToCfg = "/kubernetes-vault-client/config.yaml"
)

var (
	debug     bool
	pathToCfg string
)

func main() {
	fs := flag.NewFlagSet("", flag.ExitOnError)
	fs.BoolVar(&debug, "debug", false, "run in debug mode")
	fs.StringVar(&pathToCfg, "config", defaultPathToCfg, "path to config file")
	fs.Parse(os.Args[1:])

	if debug {
		log.SetLevel(log.DebugLevel)
	}
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})

	// Try to parse the configuration file.
	cfg, err := config.Parse(pathToCfg)
	if err != nil {
		log.Fatalf("couldn't parse the configuration file: %v", err)
	}

	// Set the value of 'Debug' on the unmarshalled configuration.
	cfg.Debug = debug
}
