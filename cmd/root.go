package cmd

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "tlsmonitor",
	Short: "Monitoring certificate expiration",
	Long: `TLS Monitor will parse certificate to get the expiration date
                it can expose metrics in prometheus format.`,
}

var Debug bool

func Execute() {
	log.SetFormatter(&log.JSONFormatter{})
	rootCmd.PersistentFlags().BoolVarP(&Debug, "debug", "d", false, "enable debug logs")
	if err := rootCmd.Execute(); err != nil {
		log.WithError(err).Error("an error occurred")
		os.Exit(1)
	}
}
