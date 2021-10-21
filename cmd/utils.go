import (
	"tlsmonitor/pkg/config"
	"tlsmonitor/pkg/metrics"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func LoadConfig() (error, config.Config) {
	var serverConfig config.Config

	viper.SetConfigFile(ConfigPath)
	log.Debug("Config path; %s", ConfigPath)
	if err := viper.ReadInConfig(); err != nil {
		log.WithError(err).Error("Cannot read: ", ConfigPath)
		return err, nil
	}

	err := viper.Unmarshal(&serverConfig)
	if err != nil {
		log.WithError(err).Error("unable to decode into struct")
		return err, nil
	}

	log.Debug(serverConfig)
	return nil, serverConfig
}

func StartMetrics(serverConfig *config.Config) error {
	if serverConfig.Metrics.Enabled {
		metrics.InitMetrics()
		go func() {
			metrics.ServeMetrics(serverConfig.Metrics)
		}()
	}
}
