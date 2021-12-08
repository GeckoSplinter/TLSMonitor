package main

import (
	"tlsmonitor/cmd"

	"github.com/DataDog/datadog-go/statsd"
	log "github.com/sirupsen/logrus"
	_ "go.uber.org/automaxprocs"
)

func main() {
	log.SetFormatter(&log.JSONFormatter{})
	cmd.Execute()

}
