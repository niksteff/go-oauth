package config

import (
	"errors"
	"fmt"

	"github.com/niksteff/go-reserv/internal/auth"
	"github.com/spf13/viper"
)

type App struct {
	Environment string // the apps environment e.g. "dev" or "prod"
}

type Configuration struct {
	Auth auth.Config // auth configuration including auth0
}

func Load() (Configuration, error) {
	var err error

	viper.AddConfigPath(".")
	viper.SetConfigName("service.config")
	viper.SetConfigType("yaml")

	err = viper.ReadInConfig()
	if err != nil {
		var notFound viper.ConfigFileNotFoundError
		if errors.As(err, &notFound) {
			return Configuration{}, fmt.Errorf("fatal could not find config file: %w", notFound)
		}

		return Configuration{}, fmt.Errorf("fatal error config file: %s \n", err)
	}

	var conf Configuration
	err = viper.Unmarshal(&conf)
	if err != nil {
		return Configuration{}, fmt.Errorf("fatal loading config: %w", err)
	}

	return conf, nil
}
