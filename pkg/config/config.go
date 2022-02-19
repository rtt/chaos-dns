package config

import (
	"flag"
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	Port        int
	JsonLogging bool
	File        string
}

const (
	jsonLoggingConfigKey = "JSON_LOGGING"
)

func ParseCliArgs() (config Config, err error) {
	defer func() {
		if r := recover(); r != nil {
			switch pval := r.(type) {
			default:
				err = fmt.Errorf("%v", pval)
			}
		}
	}()

	flag.IntVar(&config.Port, "port", getIntEnv("PORT", 53), "Port to listen on")
	flag.BoolVar(&config.JsonLogging, "json-logging", getBoolEnv(jsonLoggingConfigKey, false), "If true, output logs in json format")
	flag.StringVar(&config.File, "file", getEnv("FILE", ""), "Dig query/response to work with")
	flag.Parse()

	return config, err
}

func getIntEnv(key string, fallback int) int {
	envStrValue := getEnv(key, "")
	if envStrValue == "" {
		return fallback
	}

	envIntValue, err := strconv.Atoi(envStrValue)
	if err != nil {
		panic("Env Var " + key + " must be an integer")
	}

	return envIntValue
}

func getBoolEnv(key string, fallback bool) bool {
	envStrValue := getEnv(key, "")
	if envStrValue == "" {
		return fallback
	}

	envBoolValue, err := strconv.ParseBool(envStrValue)
	if err != nil {
		panic("Env Var " + key + " must be either true or false")
	}

	return envBoolValue
}

func getEnv(key string, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		if value != "" {
			return value
		}
	}

	return fallback
}
