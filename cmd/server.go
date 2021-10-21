package cmd

import (
	"time"
	"tlsmonitor/pkg/config"
	"tlsmonitor/pkg/tls"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(serverCmd)
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start monitor and metrics endpoint",
	RunE: func(cmd *cobra.Command, args []string) error {
		var serverConfig config.Config

		if Debug {
			log.SetLevel(log.DebugLevel)
		}

		//viper.SetConfigFile(ConfigPath)
		//log.Debug("Config path; %s", ConfigPath)
		//if err := viper.ReadInConfig(); err != nil {
		//	log.WithError(err).Error("Cannot read: ", ConfigPath)
		//}

		//err := viper.Unmarshal(&serverConfig)
		//if err != nil {
		//	log.WithError(err).Error("unable to decode into struct")
		//}

		//if serverConfig.Metrics.Enabled {
		//	metrics.InitMetrics()
		//	go func() {
		//		metrics.ServeMetrics(serverConfig.Metrics)
		//	}()
		//}

		//go func() {
		//	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		//		fmt.Fprint(w, "200 - healthy")
		//	},
		//	)
		//	http.ListenAndServe(":8080", nil)
		//}()

		//log.Debug(serverConfig)

		serverConfig

		tls.StartChecks(&serverConfig) //Run it a first time before tick
		for range time.Tick(time.Hour * time.Duration(serverConfig.ChecksFrequency)) {
			tls.StartChecks(&serverConfig)
		}

		return nil
	},
}
