package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/rtt/chaos-dns/pkg/config"
	"github.com/rtt/chaos-dns/pkg/queries"

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

	config, err := config.ParseCliArgs()

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to parse cli args")
	}

	if !config.JsonLogging {
		log.Info().Msg("Logging will be human readable")
	}

	if config.File != "" {
		// work from file then quit
		log.Info().Msgf("Loading file: %s", config.File)
		buf := queries.NewBytePacketBufferFromFile(config.File)
		header, query, responses, _ := queries.DecodeBuffer(buf)

		log.Info().Msgf("Query id: ", header.QueryIdHex())
		log.Info().Msgf("Is response:", header.IsResponse())
		log.Info().Msgf("Opcode:", header.opcode)
		log.Info().Msg("AA Authoritative:", header.isAuthoritative)
		log.Info().Msg("TC Truncated:", header.isTruncatedMessage)
		log.Info().Msg("RD Recursion desired:", header.recursionDesired)
		log.Info().Msg("RD Recursion available:", header.recursionAvailable)
		log.Info().Msg("DNSSEC:", header.dnsSec)
		log.Info().Msg("Res code:", header.resCode, header.resCodeStr())
		log.Info().Msg("Query count:", header.questions)
		log.Info().Msg("Answer count:", header.answers)
		log.Info().Msg("Authority count:", header.authoritative)
		log.Info().Msg("Additional count:", header.additional)

		if query != nil {
			log.Info().Msg("Query:", query.name)
			log.Info().Msg("Query type:", query.rTypeStr())
			log.Info().Msg("Query class: IN", query.class)
		}

		if responses != nil {
			for _, r := range *responses {
				log.Info().Msg("Response record class:", r.recordClass)
				log.Info().Msg("Response record type:", r.recordType, getRecordTypeName(r.recordType))
				log.Info().Msg("TTL: ", r.ttl)
				log.Info().Msg(r.asStr())
			}
		}
	}

}
