package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/rtt/chaos-dns/pkg/config"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	timeFormat = "2006/01/02 15:04:05"
)

func main() {

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: timeFormat, NoColor: true})

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM)
	defer signal.Stop(signalChan)

	nthConfig, err := config.ParseCliArgs()

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to parse cli args")
	}

	if !nthConfig.JsonLogging {
		log.Info().Msg("Logging will be human readable")
	}

}
