package main

import (
	"context"
	"flag"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/travelaudience/kubernetes-vault-client/pkg/config"
	"github.com/travelaudience/kubernetes-vault-client/pkg/mode"
	"github.com/travelaudience/kubernetes-vault-client/pkg/mode/initc"
	"github.com/travelaudience/kubernetes-vault-client/pkg/vault"
)

const (
	defaultPathToCfg = "/config/config.yaml"
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

	// Configure logging level and formatting.
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

	// Create a 'VaultClient' using the unmarshalled configuration.
	client, err := vault.NewClient(cfg)
	if err != nil {
		log.Fatalf("couldn't create vault client: %v", err)
	}

	switch cfg.Mode.Name {
	case config.InitCModeName:

		// Runs the app in 'initC' mode. This is intended to be used as an init
		// container. The app will authenticate with Vault, dump the
		// requested secrets to the specified paths and then exit.

		// Grab the 'InitCModeConfig' containing the proxy's configuration.
		modeCfg := cfg.Mode.Data.(config.InitCModeConfig)

		// Grab an empty context.
		ctx := context.Background()

		// Dump the requested secrets and exit.
		ctx = context.WithValue(ctx, mode.Client, client)
		initc.Run(ctx, &modeCfg)

	default:
		// Shouldn't be reached.
		log.Fatalf("unknown mode name '%s'", cfg.Mode.Name)
	}
}
