package cmd

import (
	"time"
	"tlsmonitor/pkg/config"
	"tlsmonitor/pkg/tls"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(directCmd)
}

var directCmd = &cobra.Command{
	Use:   "direct",
	Short: "Only run the certificate checks and stop",
	RunE: func(cmd *cobra.Command, args []string) error {
		var serverConfig config.Config

		if Debug {
			log.SetLevel(log.DebugLevel)
		}

		viper.SetConfigFile(ConfigPath)
		log.Debug("Config path: ", ConfigPath)
		if err := viper.ReadInConfig(); err != nil {
			log.WithError(err).Error("Cannot read: ", ConfigPath)
		}

		err := viper.Unmarshal(&serverConfig)
		if err != nil {
			log.WithError(err).Error("unable to decode into struct")
		}

		log.Debug(serverConfig)
		tls.StartChecks(&serverConfig)

		if serverConfig.Metrics.WaitScraping {
			time.Sleep(time.Second * 60)
		}

		return nil
	},
}
